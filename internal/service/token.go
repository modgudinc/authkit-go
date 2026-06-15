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

	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/model"
)

// lastUsedUpdateTimeout bounds the best-effort, fire-and-forget "last used"
// timestamp updates so a detached goroutine can never hang on a stuck connection.
const lastUsedUpdateTimeout = 5 * time.Second

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
			log.Warn("skipping last_used_at update: too many in flight", "what", what)
		}
		return
	}

	bgCtx := context.WithoutCancel(parent)
	go func() {
		defer func() { <-lastUsedUpdateSlots }()
		defer func() {
			if rec := recover(); rec != nil && log != nil {
				log.Error("panic updating last_used_at", "what", what, "panic", rec)
			}
		}()
		uctx, cancel := context.WithTimeout(bgCtx, lastUsedUpdateTimeout)
		defer cancel()
		if err := fn(uctx); err != nil && log != nil {
			log.Warn("failed to update last_used_at", "what", what, "error", err.Error())
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
}

// NewTokenService creates a new TokenService instance
//
// Parameters:
//   - repo: Repository instance for refresh token storage
//   - jwtService: JWT service for access token generation/validation
//   - refreshExpiry: Refresh token expiration duration
//   - refreshTokenHMACSecret: Secret for HMAC-SHA256 hashing of refresh tokens
//   - logger: Optional logger for structured logging
func NewTokenService(
	repo *repository.Repository,
	jwtService *JWTService,
	refreshExpiry time.Duration,
	refreshTokenHMACSecret string,
	logger logger.Logger,
) *TokenService {
	return &TokenService{
		jwtService:             jwtService,
		repo:                   repo,
		refreshExpiry:          refreshExpiry,
		refreshTokenHMACSecret: refreshTokenHMACSecret,
		logger:                 logger,
	}
}

// GenerateTokenPair generates both access token (JWT) and refresh token
//
// Parameters:
//   - ctx: Context for database operations
//   - user: User model for JWT claims
//   - sessionInfo: Session metadata (IP, user agent, device)
//
// Returns:
//   - TokenPairResponse with access token, refresh token, and expiration
//
// Flow:
//  1. Generate JWT access token via JWTService
//  2. Generate random refresh token (32 bytes, base64-encoded)
//  3. Hash refresh token with HMAC-SHA256 (defense in depth)
//  4. Store hash in database with session metadata
//  5. Return plaintext tokens (refresh token only visible here)
//
// Example:
//
//	response, err := tokenService.GenerateTokenPair(ctx, user, sessionInfo)
//	if err != nil {
//	    return fmt.Errorf("failed to generate tokens: %w", err)
//	}
//	// Return response.AccessToken and response.RefreshToken to client
func (s *TokenService) GenerateTokenPair(
	ctx context.Context,
	user *model.User,
	sessionInfo *model.SessionInfo,
) (*model.TokenPairResponse, error) {
	if s.logger != nil {
		s.logger.Info("Generating token pair",
			"user_id", user.ID.String(),
			"email", maskEmail(user.Email),
			"tenant_id", user.TenantID,
		)
	}

	// 1. Generate JWT access token
	accessToken, err := s.jwtService.GenerateAccessToken(user)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to generate access token", "error", err.Error())
		}
		return nil, sanitizeError(nil, "generate access token", err)
	}

	// 2. Generate random refresh token
	refreshToken, err := s.jwtService.GenerateRefreshToken()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to generate refresh token", "error", err.Error())
		}
		return nil, sanitizeError(nil, "generate refresh token", err)
	}

	// 3. Hash refresh token with HMAC-SHA256
	tokenHash := s.hashToken(refreshToken)

	// 4. Store hash in database with session metadata
	expiresAt := time.Now().Add(s.refreshExpiry)

	var ipAddress, userAgent, deviceName *string
	if sessionInfo != nil {
		if sessionInfo.IPAddress != "" {
			ipAddress = &sessionInfo.IPAddress
		}
		if sessionInfo.UserAgent != "" {
			userAgent = &sessionInfo.UserAgent
		}
		if sessionInfo.DeviceName != "" {
			deviceName = &sessionInfo.DeviceName
		}
	}

	_, err = s.repo.CreateRefreshToken(ctx, model.CreateRefreshTokenRequest{
		UserID:     user.ID,
		TokenHash:  tokenHash,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		DeviceName: deviceName,
		ExpiresAt:  expiresAt,
	})
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to store refresh token", "error", err.Error())
		}
		return nil, sanitizeError(nil, "store refresh token", err)
	}

	if s.logger != nil {
		s.logger.Info("Token pair generated successfully",
			"user_id", user.ID.String(),
			"access_expires_in", s.jwtService.GetAccessExpiry().Seconds(),
			"refresh_expires_in", s.refreshExpiry.Seconds(),
		)
	}

	return &model.TokenPairResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.jwtService.GetAccessExpiry().Seconds()),
	}, nil
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
	if s.logger != nil {
		s.logger.Info("Validating refresh token")
	}

	// 1. Hash provided token
	tokenHash := s.hashToken(tokenString)

	// 2. Lookup token in database
	storedToken, err := s.repo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("Refresh token not found or expired", "error", err.Error())
		}
		return nil, sanitizeError(nil, "lookup refresh token", err)
	}

	// 3. Fetch user by user_id (no tenant_id needed since user_id is unique)
	user, err := s.repo.GetByIDOnly(ctx, storedToken.UserID)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to fetch user for refresh token", "error", err.Error())
		}
		return nil, sanitizeError(nil, "fetch user for refresh token", err)
	}

	// 4. Reject disabled/locked accounts so a cut-off account cannot be treated
	// as valid even if a consumer uses this method directly to build a session.
	if !user.IsEnabled || isUserLocked(user) {
		if s.logger != nil {
			s.logger.Warn("Refresh token rejected: account is not active",
				"user_id", user.ID.String(),
				"is_enabled", user.IsEnabled,
				"is_locked", user.IsLocked,
			)
		}
		return nil, fmt.Errorf("account is not active: %w", model.ErrInvalidRefreshToken)
	}

	// 5. Update last_used_at as a bounded, best-effort background write (see
	// runBoundedLastUsedUpdate): detached from the request, timeout-bounded, and
	// capped in concurrency so a burst of validations can't fan out unbounded.
	tokenID := storedToken.ID
	runBoundedLastUsedUpdate(ctx, s.logger, "refresh token", func(uctx context.Context) error {
		return s.repo.UpdateLastUsed(uctx, tokenID)
	})

	if s.logger != nil {
		s.logger.Info("Refresh token validated successfully",
			"user_id", user.ID.String(),
			"token_id", storedToken.ID.String(),
		)
	}

	return user, nil
}

// RefreshTokenPair validates refresh token and generates new token pair (token rotation)
//
// Parameters:
//   - ctx: Context for database operations
//   - refreshToken: Current refresh token from client
//   - sessionInfo: Session metadata for new refresh token
//
// Returns:
//   - New token pair with rotated refresh token
//   - Error if validation fails
//
// Flow:
//  1. Validate current refresh token
//  2. Get user
//  3. Delete old refresh token (revoke it)
//  4. Generate new token pair
//  5. Return new tokens
//
// Example:
//
//	response, err := tokenService.RefreshTokenPair(ctx, oldRefreshToken, sessionInfo)
//	if err != nil {
//	    return fmt.Errorf("token refresh failed: %w", err)
//	}
//	// Return new tokens to client
func (s *TokenService) RefreshTokenPair(
	ctx context.Context,
	refreshToken string,
	sessionInfo *model.SessionInfo,
) (*model.TokenPairResponse, error) {
	if s.logger != nil {
		s.logger.Info("Refreshing token pair")
	}

	// 1. Generate the replacement refresh token before entering the DB transaction.
	newRefreshToken, err := s.jwtService.GenerateRefreshToken()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to generate replacement refresh token", "error", err.Error())
		}
		return nil, sanitizeError(nil, "generate replacement refresh token", err)
	}

	oldTokenHash := s.hashToken(refreshToken)
	newTokenHash := s.hashToken(newRefreshToken)
	expiresAt := time.Now().Add(s.refreshExpiry)

	var ipAddress, userAgent, deviceName *string
	if sessionInfo != nil {
		if sessionInfo.IPAddress != "" {
			ipAddress = &sessionInfo.IPAddress
		}
		if sessionInfo.UserAgent != "" {
			userAgent = &sessionInfo.UserAgent
		}
		if sessionInfo.DeviceName != "" {
			deviceName = &sessionInfo.DeviceName
		}
	}

	// 2. Atomically consume the old refresh token and store the replacement.
	user, tokenID, err := s.repo.RotateRefreshToken(ctx, oldTokenHash, model.CreateRefreshTokenRequest{
		TokenHash:  newTokenHash,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		DeviceName: deviceName,
		ExpiresAt:  expiresAt,
	})
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("Failed to rotate refresh token", "error", err.Error())
		}
		// Preserve the underlying sentinel (model.ErrInvalidRefreshToken or
		// model.ErrRefreshTokenReuse) so callers can distinguish a benign
		// invalid/expired token from a detected reuse/theft event.
		return nil, sanitizeError(nil, "rotate refresh token", err)
	}

	// 3. Re-check account standing before minting a new access token.
	// The refresh path does not go through AuthService.ValidateJWT, so without
	// this gate a disabled or locked account could keep minting fresh access
	// tokens for the entire lifetime of its refresh token. RotateRefreshToken
	// has already persisted the replacement token inside its transaction, so on
	// rejection we revoke the user's entire refresh-token family to ensure a
	// cut-off account cannot continue refreshing.
	if !user.IsEnabled || isUserLocked(user) {
		if revokeErr := s.repo.DeleteByUserID(ctx, user.ID); revokeErr != nil && s.logger != nil {
			s.logger.Warn("Failed to revoke refresh tokens for inactive account during refresh",
				"user_id", user.ID.String(),
				"error", revokeErr.Error(),
			)
		}
		if s.logger != nil {
			s.logger.Warn("Refresh denied: account is not active",
				"user_id", user.ID.String(),
				"is_enabled", user.IsEnabled,
				"is_locked", user.IsLocked,
			)
		}
		return nil, fmt.Errorf("account is not active: %w", model.ErrInvalidRefreshToken)
	}

	// 4. Generate a new access token for the user tied to the consumed token.
	accessToken, err := s.jwtService.GenerateAccessToken(user)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to generate rotated access token", "error", err.Error())
		}
		if revokeErr := s.repo.DeleteByTokenHash(ctx, newTokenHash); revokeErr != nil && s.logger != nil {
			s.logger.Warn("Failed to revoke rotated refresh token after access token error",
				"token_id", tokenID.String(),
				"error", revokeErr.Error(),
			)
		}
		return nil, sanitizeError(nil, "generate rotated access token", err)
	}

	if s.logger != nil {
		s.logger.Info("Refresh token rotated successfully",
			"user_id", user.ID.String(),
			"token_id", tokenID.String(),
		)
	}

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
// This operation is idempotent: revoking a token that no longer exists (because
// it was already revoked, rotated, or expired) is treated as success and returns
// nil. Only a genuine storage/driver fault yields a non-nil (sanitized) error.
//
// Example:
//
//	err := tokenService.RevokeRefreshToken(ctx, refreshToken)
//	if err != nil {
//	    return fmt.Errorf("failed to revoke token: %w", err)
//	}
func (s *TokenService) RevokeRefreshToken(ctx context.Context, tokenString string) error {
	if s.logger != nil {
		s.logger.Info("Revoking refresh token")
	}

	tokenHash := s.hashToken(tokenString)
	if err := s.repo.DeleteByTokenHash(ctx, tokenHash); err != nil {
		// Logout is idempotent: a token that no longer exists is already revoked,
		// so treat a not-found delete as success rather than an error.
		if errors.Is(err, model.ErrNotFound) {
			if s.logger != nil {
				s.logger.Info("Refresh token already revoked")
			}
			return nil
		}
		if s.logger != nil {
			s.logger.Error("Failed to revoke refresh token", "error", err.Error())
		}
		return sanitizeError(nil, "revoke refresh token", err)
	}

	if s.logger != nil {
		s.logger.Info("Refresh token revoked successfully")
	}

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
// Precondition: the caller MUST have already verified that userID belongs to the
// caller's tenant. This method scopes by user_id only and does not re-check
// tenant membership (refresh tokens are not tenant-columned); passing a
// caller-supplied id without that check is a cross-tenant authorization gap.
//
// Example:
//
//	err := tokenService.RevokeAllUserTokens(ctx, userID)
//	if err != nil {
//	    return fmt.Errorf("failed to revoke all tokens: %w", err)
//	}
func (s *TokenService) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	if s.logger != nil {
		s.logger.Info("Revoking all refresh tokens for user", "user_id", userID)
	}

	if err := s.repo.DeleteByUserID(ctx, userID); err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to revoke all user tokens", "error", err.Error())
		}
		return sanitizeError(nil, "revoke all user tokens", err)
	}

	if s.logger != nil {
		s.logger.Info("All refresh tokens revoked successfully", "user_id", userID)
	}

	return nil
}

// CleanupExpiredTokens removes expired refresh tokens from the database
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
//	count, err := tokenService.CleanupExpiredTokens(ctx)
//	if err != nil {
//	    return fmt.Errorf("cleanup failed: %w", err)
//	}
//	fmt.Printf("Deleted %d expired tokens\n", count)
func (s *TokenService) CleanupExpiredTokens(ctx context.Context) (int64, error) {
	if s.logger != nil {
		s.logger.Info("Cleaning up expired refresh tokens")
	}

	count, err := s.repo.DeleteExpired(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to cleanup expired tokens", "error", err.Error())
		}
		return 0, sanitizeError(nil, "cleanup expired tokens", err)
	}

	if s.logger != nil {
		s.logger.Info("Expired tokens cleaned up successfully", "count", count)
	}

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
