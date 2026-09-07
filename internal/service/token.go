// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
)

// lastUsedUpdateTimeout bounds the best-effort, fire-and-forget "last used"
// timestamp updates so a detached goroutine can never hang on a stuck connection.
const lastUsedUpdateTimeout = 5 * time.Second

// cleanupTimeout bounds the compensating security cleanups in RefreshTokenPair
// (family revoke on an inactive account, rotated-token revoke after an error). They
// run on a context detached from the request's cancellation so a client disconnect
// cannot leave a cut-off account's tokens or an orphaned rotated token in place.
const cleanupTimeout = 5 * time.Second

// cleanupContext returns a context detached from parent's cancellation (its values
// preserved) and bounded by cleanupTimeout, for compensating writes that must still
// run after the request is cancelled.
func cleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), cleanupTimeout)
}

// maxConcurrentLastUsedUpdates caps how many best-effort "last used" updates may
// be in flight at once. Without a bound, a burst of token/API-key validations
// would fan out one detached goroutine each, all contending on the rw pool.
const maxConcurrentLastUsedUpdates = 64

// lastUsedUpdateSlots is the semaphore enforcing maxConcurrentLastUsedUpdates,
// shared across the service package's validation paths.
var lastUsedUpdateSlots = make(chan struct{}, maxConcurrentLastUsedUpdates)

// runBoundedLastUsedUpdate runs a best-effort "last used" write in a background
// goroutine that outlives the request (the request context's cancellation is
// detached with WithoutCancel, its values preserved) but is bounded two ways:
// by lastUsedUpdateSlots (when full, the update is skipped — the next validation
// will refresh the timestamp) and by lastUsedUpdateTimeout (so it can't hang).
// Any panic is recovered so a background failure can never crash the host.
func runBoundedLastUsedUpdate(parent context.Context, log logger.Logger, what string, fn func(context.Context) error) {
	select {
	case lastUsedUpdateSlots <- struct{}{}:
	default:
		if log != nil {
			log.Warn(parent, "skipping last_used_at update: too many in flight", "what", what)
		}
		return
	}

	bgCtx := context.WithoutCancel(parent)
	go func() {
		defer func() { <-lastUsedUpdateSlots }()
		defer func() {
			if rec := recover(); rec != nil && log != nil {
				log.Error(bgCtx, "panic updating last_used_at", "what", what, "panic", rec)
			}
		}()
		uctx, cancel := context.WithTimeout(bgCtx, lastUsedUpdateTimeout)
		defer cancel()
		if err := fn(uctx); err != nil && log != nil {
			log.Warn(uctx, "failed to update last_used_at", "what", what, "error", err.Error())
		}
	}()
}

// TokenService handles both JWT and refresh token management
// Combines JWT generation/validation with refresh token storage and rotation
type TokenService struct {
	jwtService             *JWTService
	repo                   *repository.Repository
	refreshExpiry          time.Duration
	refreshTokenHMACSecret string // Secret for HMAC-SHA256 hashing of refresh tokens
	logger                 logger.Logger
	metrics                metrics.Metrics
}

// NewTokenService creates a new TokenService instance
//
// Parameters:
//   - repo: Repository instance for refresh token storage
//   - jwtService: JWT service for access token generation/validation
//   - refreshExpiry: Refresh token expiration duration
//   - refreshTokenHMACSecret: Secret for HMAC-SHA256 hashing of refresh tokens
//   - logger: Optional logger for structured logging
//   - metrics: Optional counter sink for refresh-token reuse events (may be nil)
func NewTokenService(
	repo *repository.Repository,
	jwtService *JWTService,
	refreshExpiry time.Duration,
	refreshTokenHMACSecret string,
	logger logger.Logger,
	metrics metrics.Metrics,
) *TokenService {
	return &TokenService{
		jwtService:             jwtService,
		repo:                   repo,
		refreshExpiry:          refreshExpiry,
		refreshTokenHMACSecret: refreshTokenHMACSecret,
		logger:                 ensureLogger(logger),
		metrics:                metrics,
	}
}

// GenerateTokenPair generates a workspace-scoped access token (JWT) plus a new
// identity-session refresh token.
//
// Parameters:
//   - ctx: Context for database operations
//   - user: the global identity (JWT identity claims)
//   - membership: the active membership the access token is scoped to (tenant + roles)
//   - sessionInfo: Session metadata (IP, user agent, device)
//
// Returns:
//   - TokenPairResponse with access token, refresh token, and expiration
//
// The access token is workspace-scoped (user + membership); the refresh token opens
// a new identity session (user-scoped, no tenant). From one refresh token a caller
// can mint access tokens for any of the user's memberships (see MintAccessToken).
//
// Example:
//
//	response, err := tokenService.GenerateTokenPair(ctx, user, membership, sessionInfo)
//	if err != nil {
//	    return fmt.Errorf("failed to generate tokens: %w", err)
//	}
//	// Return response.AccessToken and response.RefreshToken to client
func (s *TokenService) GenerateTokenPair(
	ctx context.Context,
	user *model.User,
	membership *model.Membership,
	sessionInfo *model.SessionInfo,
) (*model.TokenPairResponse, error) {
	s.logger.Info(ctx, "Generating token pair",
		"user_id", user.ID,
		"email", maskEmail(user.Email),
		"tenant_id", membership.TenantID,
	)

	// 1. Mint the workspace-scoped access token (stateless; no DB write).
	accessToken, expiresIn, err := s.MintAccessToken(ctx, user, membership)
	if err != nil {
		return nil, err
	}

	// 2. Open the identity session (stores the refresh-token HMAC).
	refreshToken, err := s.CreateIdentitySession(ctx, user.ID, sessionInfo)
	if err != nil {
		return nil, err
	}

	s.logger.Info(ctx, "Token pair generated successfully",
		"user_id", user.ID,
		"access_expires_in", s.jwtService.GetAccessExpiry().Seconds(),
		"refresh_expires_in", s.refreshExpiry.Seconds(),
	)

	return &model.TokenPairResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
	}, nil
}

// MintAccessToken mints a workspace-scoped access token for user's membership and
// returns it with its lifetime in seconds. It performs NO database write — access
// tokens are stateless (only the refresh token, the identity session, is stored), so
// this is the cheap call used to issue or switch the active workspace from an
// existing session.
func (s *TokenService) MintAccessToken(ctx context.Context, user *model.User, membership *model.Membership) (string, int64, error) {
	accessToken, err := s.jwtService.GenerateAccessToken(user, membership)
	if err != nil {
		s.logger.Error(ctx, "Failed to generate access token", "error", err.Error())
		return "", 0, sanitizeError(ctx, s.logger, "generate access token", err)
	}
	return accessToken, int64(s.jwtService.GetAccessExpiry().Seconds()), nil
}

// CreateIdentitySession opens a new identity session: it generates a refresh token,
// stores its HMAC-SHA256 (a fresh token family) with the session metadata, and
// returns the plaintext refresh token (the only time it is visible). The session is
// user-scoped, not tied to any tenant — workspace access tokens are minted from it
// per membership.
func (s *TokenService) CreateIdentitySession(ctx context.Context, userID string, sessionInfo *model.SessionInfo) (string, error) {
	refreshToken, err := s.jwtService.GenerateRefreshToken()
	if err != nil {
		s.logger.Error(ctx, "Failed to generate refresh token", "error", err.Error())
		return "", sanitizeError(ctx, s.logger, "generate refresh token", err)
	}

	tokenHash := s.hashToken(refreshToken)
	expiresAt := time.Now().Add(s.refreshExpiry)
	ipAddress, userAgent, deviceName := sessionPointers(sessionInfo)

	if _, err := s.repo.CreateRefreshToken(ctx, repository.CreateRefreshTokenRequest{
		UserID:     userID,
		TokenHash:  tokenHash,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		DeviceName: deviceName,
		ExpiresAt:  expiresAt,
	}); err != nil {
		s.logger.Error(ctx, "Failed to store refresh token", "error", err.Error())
		return "", sanitizeError(ctx, s.logger, "store refresh token", err)
	}

	return refreshToken, nil
}

// sessionPointers converts a *model.SessionInfo into the nullable string pointers
// the repository stores: a nil SessionInfo or an empty field becomes a nil pointer
// (stored as SQL NULL).
func sessionPointers(sessionInfo *model.SessionInfo) (ipAddress, userAgent, deviceName *string) {
	if sessionInfo == nil {
		return nil, nil, nil
	}
	if sessionInfo.IPAddress != "" {
		ipAddress = &sessionInfo.IPAddress
	}
	if sessionInfo.UserAgent != "" {
		userAgent = &sessionInfo.UserAgent
	}
	if sessionInfo.DeviceName != "" {
		deviceName = &sessionInfo.DeviceName
	}
	return ipAddress, userAgent, deviceName
}

// ValidateRefreshToken validates a refresh token and returns the associated user
//
// Parameters:
//   - ctx: Context for database operations
//   - tokenString: Plaintext refresh token from client
//
// Returns:
//   - User associated with the refresh token
//   - Error if token is invalid, expired, or not found
//
// It enforces the same account-status gate as the rotation path: a disabled or
// locked account's refresh token is rejected. To rotate tokens, prefer
// RefreshTokenPair (which also rotates and detects reuse) rather than calling
// this and minting tokens yourself.
//
// Flow:
//  1. Hash provided token with HMAC-SHA256
//  2. Lookup token hash in database
//  3. Fetch user by user_id
//  4. Reject if the account is disabled or locked
//  5. Update last_used_at asynchronously (non-blocking)
//
// Example:
//
//	user, err := tokenService.ValidateRefreshToken(ctx, refreshToken)
//	if err != nil {
//	    return fmt.Errorf("invalid refresh token: %w", err)
//	}
func (s *TokenService) ValidateRefreshToken(ctx context.Context, tokenString string) (*model.User, error) {
	s.logger.Info(ctx, "Validating refresh token")

	// 1. Hash provided token
	tokenHash := s.hashToken(tokenString)

	// 2. Lookup token in database
	storedToken, err := s.repo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		s.logger.Warn(ctx, "Refresh token not found or expired", "error", err.Error())
		return nil, sanitizeError(ctx, s.logger, "lookup refresh token", err)
	}

	// 3. Fetch the global identity by user_id (the refresh token is user-scoped). Read
	// from the PRIMARY: the disabled/locked freeze gate below (and the MintWorkspaceToken
	// path that relies on it) must observe an admin disable/lock immediately, not after
	// replica catch-up — matching the FromPrimary reads on the other security gates.
	user, err := s.repo.GetByIDFromPrimary(ctx, storedToken.UserID)
	if err != nil {
		s.logger.Error(ctx, "Failed to fetch user for refresh token", "error", err.Error())
		return nil, sanitizeError(ctx, s.logger, "fetch user for refresh token", err)
	}

	// 4. Reject disabled/locked accounts so a cut-off account cannot be treated
	// as valid even if a consumer uses this method directly to build a session.
	if !user.IsEnabled || isUserLocked(user) {
		s.logger.Warn(ctx, "Refresh token rejected: account is not active",
			"user_id", user.ID,
			"is_enabled", user.IsEnabled,
			"is_locked", user.IsLocked,
		)
		return nil, fmt.Errorf("account is not active: %w", model.ErrInvalidRefreshToken)
	}

	// 5. Update last_used_at as a bounded, best-effort background write (see
	// runBoundedLastUsedUpdate): detached from the request, timeout-bounded, and
	// capped in concurrency so a burst of validations can't fan out unbounded.
	tokenID := storedToken.ID
	runBoundedLastUsedUpdate(ctx, s.logger, "refresh token", func(uctx context.Context) error {
		return s.repo.UpdateLastUsed(uctx, tokenID)
	})

	s.logger.Info(ctx, "Refresh token validated successfully",
		"user_id", user.ID,
		"token_id", storedToken.ID,
	)

	return user, nil
}

// RefreshTokenPair validates refresh token and generates new token pair (token rotation)
//
// Parameters:
//   - ctx: Context for database operations
//   - refreshToken: Current refresh token from client (the identity session)
//   - tenantID: Workspace the rotated access token should be scoped to (the user
//     must have an active membership there)
//   - sessionInfo: Session metadata for the new refresh token
//
// Returns:
//   - New token pair: a rotated refresh token + a workspace-scoped access token
//   - model.ErrNoActiveMembership if the identity has no active membership in tenantID
//   - Error if the refresh token is invalid/expired/reused or the account is inactive
//
// Flow:
//  1. Verify an active membership in tenantID WITHOUT consuming the refresh token
//  2. Atomically rotate the refresh token (consume old, store replacement; reuse-detecting)
//  3. Re-check account standing
//  4. Mint the workspace-scoped access token
//
// Example:
//
//	response, err := tokenService.RefreshTokenPair(ctx, oldRefreshToken, tenantID, sessionInfo)
//	if err != nil {
//	    return fmt.Errorf("token refresh failed: %w", err)
//	}
//	// Return new tokens to client
func (s *TokenService) RefreshTokenPair(
	ctx context.Context,
	refreshToken string,
	tenantID string,
	sessionInfo *model.SessionInfo,
) (*model.TokenPairResponse, error) {
	s.logger.Info(ctx, "Refreshing token pair", "tenant_id", tenantID)

	// 0. Verify the identity has an ACTIVE membership in tenantID BEFORE rotating the
	// refresh token. The refresh token is the identity session (one per login, shared
	// across all of the user's workspaces); rotating it and only then discovering the
	// user no longer belongs to tenantID would consume the presented token and strand
	// its replacement (the client never receives it), so the next refresh of ANY
	// workspace would trip reuse detection and revoke the whole family.
	//
	// The token is looked up WITHOUT filtering on revoked state: a REVOKED token is NOT
	// short-circuited here — it must fall through to RotateRefreshToken so its
	// reuse/theft detection (family revoke + token_version bump + alert) still fires. So
	// only a LIVE token gets the non-destructive membership pre-check; a missing or
	// suspended membership is rejected with ErrNoActiveMembership without touching the
	// session. The membership is read from the PRIMARY so a just-committed revoke/suspend
	// is observed immediately.
	oldTokenHash := s.hashToken(refreshToken)
	userID, revoked, err := s.repo.GetRefreshTokenUserByHash(ctx, oldTokenHash)
	if err != nil {
		s.logger.Warn(ctx, "Refresh token not found", "error", err.Error())
		return nil, sanitizeError(ctx, s.logger, "lookup refresh token", err)
	}
	var preCheckedMembership *model.Membership
	if !revoked {
		membership, mErr := s.repo.GetMembershipFromPrimary(ctx, userID, tenantID)
		if mErr != nil {
			if errors.Is(mErr, model.ErrNotFound) {
				s.logger.Warn(ctx, "Refresh denied: no membership in tenant", "user_id", userID, "tenant_id", tenantID)
				return nil, model.ErrNoActiveMembership
			}
			return nil, sanitizeError(ctx, s.logger, "load membership for refresh", mErr)
		}
		if !membership.IsActive() {
			s.logger.Warn(ctx, "Refresh denied: membership not active", "user_id", userID, "tenant_id", tenantID)
			return nil, model.ErrNoActiveMembership
		}
		preCheckedMembership = membership
	}

	// 1. Generate the replacement refresh token before entering the DB transaction.
	newRefreshToken, err := s.jwtService.GenerateRefreshToken()
	if err != nil {
		s.logger.Error(ctx, "Failed to generate replacement refresh token", "error", err.Error())
		return nil, sanitizeError(ctx, s.logger, "generate replacement refresh token", err)
	}

	newTokenHash := s.hashToken(newRefreshToken)
	expiresAt := time.Now().Add(s.refreshExpiry)
	ipAddress, userAgent, deviceName := sessionPointers(sessionInfo)

	// 2. Atomically consume the old refresh token and store the replacement.
	user, tokenID, err := s.repo.RotateRefreshToken(ctx, oldTokenHash, repository.CreateRefreshTokenRequest{
		TokenHash:  newTokenHash,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		DeviceName: deviceName,
		ExpiresAt:  expiresAt,
	})
	if err != nil {
		// Surface refresh-token reuse/theft as a distinguishable, elevated security
		// event (separate from routine invalid/expired-token failures) so operators
		// can alert on it via log level/event name and the metrics counter rather
		// than substring-matching. RotateRefreshToken has already revoked the whole
		// family and bumped the user's token_version. NOTE: this also fires on a
		// benign lost-response retry (the client never received the rotated token),
		// which is an inherent property of strict reuse detection — treat the counter
		// as "possible theft", not "confirmed theft".
		var reuseErr *model.RefreshTokenReuseError
		if errors.As(err, &reuseErr) {
			s.logger.Error(ctx, "SECURITY: refresh token reuse detected; token family revoked and all sessions invalidated",
				"event", "refresh_token_reuse",
				"user_id", reuseErr.UserID,
				"family_id", reuseErr.FamilyID,
			)
			incMetric(s.metrics, metrics.CounterRefreshReuse)
		} else {
			s.logger.Warn(ctx, "Failed to rotate refresh token", "error", err.Error())
		}
		// Preserve the underlying sentinel (model.ErrInvalidRefreshToken or
		// model.ErrRefreshTokenReuse) so callers can distinguish a benign
		// invalid/expired token from a detected reuse/theft event.
		return nil, sanitizeError(ctx, s.logger, "rotate refresh token", err)
	}

	// 3. Re-check account standing before minting a new access token.
	// The refresh path does not go through AuthService.ValidateJWT, so without
	// this gate a disabled or locked account could keep minting fresh access
	// tokens for the entire lifetime of its refresh token. RotateRefreshToken
	// has already persisted the replacement token inside its transaction, so on
	// rejection we revoke the user's entire refresh-token family to ensure a
	// cut-off account cannot continue refreshing.
	if !user.IsEnabled || isUserLocked(user) {
		// Detached cleanup: this family-revoke is a security action that must run even
		// if the request context was cancelled.
		cctx, ccancel := cleanupContext(ctx)
		revokeErr := s.repo.DeleteByUserID(cctx, user.ID)
		ccancel()
		if revokeErr != nil {
			s.logger.Warn(ctx, "Failed to revoke refresh tokens for inactive account during refresh",
				"user_id", user.ID,
				"error", revokeErr.Error(),
			)
		}
		s.logger.Warn(ctx, "Refresh denied: account is not active",
			"user_id", user.ID,
			"is_enabled", user.IsEnabled,
			"is_locked", user.IsLocked,
		)
		return nil, fmt.Errorf("account is not active: %w", model.ErrInvalidRefreshToken)
	}

	// 4. Mint the workspace-scoped access token for the membership verified in step 0.
	// We deliberately reuse that membership rather than re-loading it after the rotate:
	// re-loading and finding it suspended would force a reject AFTER the old token was
	// consumed, recreating the stranded-replacement problem step 0 avoids. If the
	// membership was revoked/role-changed in the tiny window since step 0, the minted
	// token's membership_token_version is already stale and ValidateJWT rejects it on
	// first use — a safe born-revoked token, not an authorization gap.
	//
	// preCheckedMembership is non-nil here: mint is reached only when the token was live
	// (revoked == false, so the pre-check ran) AND the rotate succeeded — a revoked token
	// would have been caught by RotateRefreshToken's reuse path above. The guard makes
	// that invariant explicit and prevents a nil deref if the flow is ever refactored.
	if preCheckedMembership == nil {
		return nil, sanitizeError(ctx, s.logger, "mint rotated access token", fmt.Errorf("internal: missing pre-checked membership for refresh"))
	}
	accessToken, err := s.jwtService.GenerateAccessToken(user, preCheckedMembership)
	if err != nil {
		s.logger.Error(ctx, "Failed to generate rotated access token", "error", err.Error())
		// Detached cleanup: drop the just-persisted rotated token even if the request
		// context was cancelled, so a token the client never received cannot linger.
		cctx, ccancel := cleanupContext(ctx)
		revokeErr := s.repo.DeleteByTokenHash(cctx, newTokenHash)
		ccancel()
		if revokeErr != nil {
			s.logger.Warn(ctx, "Failed to revoke rotated refresh token after access token error",
				"token_id", tokenID,
				"error", revokeErr.Error(),
			)
		}
		return nil, sanitizeError(ctx, s.logger, "generate rotated access token", err)
	}

	s.logger.Info(ctx, "Refresh token rotated successfully",
		"user_id", user.ID,
		"token_id", tokenID,
	)

	return &model.TokenPairResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(s.jwtService.GetAccessExpiry().Seconds()),
	}, nil
}

// RevokeRefreshToken revokes a specific refresh token
//
// Parameters:
//   - ctx: Context for database operations
//   - tokenString: Plaintext refresh token to revoke
//
// # Used for single session logout
//
// The token is soft-revoked (its row is retained with revoked_at set), not deleted,
// so that if a stolen-then-logged-out token is later replayed, RotateRefreshToken
// detects it as reuse (ErrRefreshTokenReuse) and revokes the whole family — the same
// theft-detection guarantee that token rotation provides. The retained row is
// cleaned up by CleanupExpired after expiry.
//
// This operation is idempotent: revoking a token that is no longer active (because
// it was already revoked, rotated, or expired/cleaned up) is treated as success and
// returns nil. Only a genuine storage/driver fault yields a non-nil (sanitized) error.
//
// Example:
//
//	err := tokenService.RevokeRefreshToken(ctx, refreshToken)
//	if err != nil {
//	    return fmt.Errorf("failed to revoke token: %w", err)
//	}
func (s *TokenService) RevokeRefreshToken(ctx context.Context, tokenString string) error {
	s.logger.Info(ctx, "Revoking refresh token")

	tokenHash := s.hashToken(tokenString)
	if err := s.repo.RevokeByTokenHash(ctx, tokenHash); err != nil {
		// Logout is idempotent: a token that is no longer active is already revoked,
		// so treat a not-found soft-revoke as success rather than an error.
		if errors.Is(err, model.ErrNotFound) {
			s.logger.Info(ctx, "Refresh token already revoked")
			return nil
		}
		s.logger.Error(ctx, "Failed to revoke refresh token", "error", err.Error())
		return sanitizeError(ctx, s.logger, "revoke refresh token", err)
	}

	s.logger.Info(ctx, "Refresh token revoked successfully")

	return nil
}

// RevokeAllUserTokens revokes all refresh tokens for a user
//
// Parameters:
//   - ctx: Context for database operations
//   - userID: User UUID
//
// Used for "logout from all devices" functionality
//
// This method is intentionally NOT part of the public TokenService interface
// (services.go) — it is reachable only internally, via AuthService.LogoutAll.
//
// It scopes by user_id only (refresh tokens are the identity session and carry no
// tenant column) and performs no authorization check. AuthService.LogoutAll is the
// identity-level entry point: it calls IncrementTokenVersion(ctx, userID) first (a
// non-existent user fails closed with ErrNotFound) and then this method. The caller of
// LogoutAll is responsible for authorizing that it may act on userID.
//
// Example:
//
//	err := tokenService.RevokeAllUserTokens(ctx, userID)
//	if err != nil {
//	    return fmt.Errorf("failed to revoke all tokens: %w", err)
//	}
func (s *TokenService) RevokeAllUserTokens(ctx context.Context, userID string) error {
	s.logger.Info(ctx, "Revoking all refresh tokens for user", "user_id", userID)

	if err := s.repo.DeleteByUserID(ctx, userID); err != nil {
		s.logger.Error(ctx, "Failed to revoke all user tokens", "error", err.Error())
		return sanitizeError(ctx, s.logger, "revoke all user tokens", err)
	}

	s.logger.Info(ctx, "All refresh tokens revoked successfully", "user_id", userID)

	return nil
}

// CleanupExpired removes expired refresh tokens from the database
//
// Parameters:
//   - ctx: Context for database operations
//
// Returns:
//   - Number of tokens deleted
//   - Error if cleanup fails
//
// # This should be run periodically (e.g., via cron job) to maintain database hygiene
//
// Example:
//
//	count, err := tokenService.CleanupExpired(ctx)
//	if err != nil {
//	    return fmt.Errorf("cleanup failed: %w", err)
//	}
//	fmt.Printf("Deleted %d expired tokens\n", count)
func (s *TokenService) CleanupExpired(ctx context.Context) (int64, error) {
	s.logger.Info(ctx, "Cleaning up expired refresh tokens")

	count, err := s.repo.DeleteExpired(ctx)
	if err != nil {
		s.logger.Error(ctx, "Failed to cleanup expired tokens", "error", err.Error())
		return 0, sanitizeError(ctx, s.logger, "cleanup expired tokens", err)
	}

	s.logger.Info(ctx, "Expired tokens cleaned up successfully", "count", count)

	return count, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// hashToken generates HMAC-SHA256 hash of a token for secure storage
// Uses HMAC for defense in depth - database compromise alone cannot validate tokens
func (s *TokenService) hashToken(token string) string {
	h := hmac.New(sha256.New, []byte(s.refreshTokenHMACSecret))
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}

// isUserLocked reports whether an account should be treated as locked right now,
// mirroring the semantics in AuthService.ValidateJWT: a lock whose locked_until
// has already passed is treated as expired (the account is unlocked on the next
// login), so it does not count as locked here.
func isUserLocked(user *model.User) bool {
	if !user.IsLocked {
		return false
	}
	if user.LockedUntil != nil && time.Now().After(*user.LockedUntil) {
		return false
	}
	return true
}
