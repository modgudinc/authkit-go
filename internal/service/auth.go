// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
	"github.com/modgudinc/authkit-go/ratelimit"
)

// authRepository is the subset of the repository used by AuthService. Depending on
// an interface (rather than the concrete *repository.Repository) lets the
// security-critical auth logic be unit-tested with an in-memory fake. All identity
// reads/writes are keyed by the global user id or globally-unique email; the
// membership methods back the workspace-scoping checks of the decoupled model.
type authRepository interface {
	GetByEmailFromPrimary(ctx context.Context, email string) (*model.User, error)
	GetByIDFromPrimary(ctx context.Context, userID string) (*model.User, error)
	Unlock(ctx context.Context, userID string) error
	RegisterFailedLogin(ctx context.Context, userID string, maxAttempts int, lockDuration time.Duration) (int, bool, error)
	UpdateLastLogin(ctx context.Context, userID string) error
	SetPasswordAndBumpTokenVersion(ctx context.Context, userID, hashedPassword string) error
	IncrementTokenVersion(ctx context.Context, userID string) error
	GetMembershipFromPrimary(ctx context.Context, userID, tenantID string) (*model.Membership, error)
	ListMembershipsByUser(ctx context.Context, userID string) ([]*model.Membership, error)
}

// AuthService handles user authentication operations.
//
// Identity vs. workspace: authentication is against the GLOBAL identity (email +
// password); authorization to a workspace is the membership. A login authenticates
// the identity (one refresh-token session) and mints WORKSPACE-SCOPED access tokens
// for the user's active memberships. Switching workspace mints a new access token
// from the same session (no re-login).
type AuthService struct {
	repo            authRepository
	passwordService *PasswordService
	tokenService    *TokenService
	jwtService      *JWTService
	logger          logger.Logger
	metrics         metrics.Metrics
	rateLimiter     ratelimit.RateLimiter
}

const (
	// MaxFailedLoginAttempts before account is locked
	MaxFailedLoginAttempts = 5
	// LockDuration is how long an account remains locked after max failed attempts
	LockDuration = 30 * time.Minute
)

// NewAuthService creates a new AuthService instance
//
// Parameters:
//   - repo: Repository instance for database operations
//   - passwordService: Password hashing and verification service
//   - tokenService: Token generation and management service
//   - jwtService: JWT validation service
//   - logger: Optional logger for structured logging
//   - metrics: Optional counter sink for login/lockout events (may be nil)
//   - rateLimiter: Optional throttle for Login/RefreshToken (may be nil)
func NewAuthService(
	repo *repository.Repository,
	passwordService *PasswordService,
	tokenService *TokenService,
	jwtService *JWTService,
	logger logger.Logger,
	metrics metrics.Metrics,
	rateLimiter ratelimit.RateLimiter,
) *AuthService {
	return &AuthService{
		repo:            repo,
		passwordService: passwordService,
		tokenService:    tokenService,
		jwtService:      jwtService,
		logger:          ensureLogger(logger),
		metrics:         metrics,
		rateLimiter:     rateLimiter,
	}
}

// authenticateIdentity verifies email+password against the GLOBAL identity and
// returns the authenticated user. It applies the account-status gates (disabled /
// locked, with auto-unlock when locked_until has elapsed) and the per-account
// failed-login lockout exactly as before. Every failure is collapsed into
// ErrInvalidCredentials (the specific reason is logged) and timing is equalized with
// a dummy bcrypt compare on the not-found / disabled / locked paths, so an
// unauthenticated caller cannot distinguish them (no account / state enumeration). On
// success it resets the failed-login count (if any) and updates last_login
// (best-effort). It does NOT check workspace membership — that is the caller's gate.
func (s *AuthService) authenticateIdentity(ctx context.Context, email, password string) (*model.User, error) {
	// Read from the PRIMARY: the is_enabled/is_locked gate must observe an admin
	// disable/lock (or an auto-lock just written by RegisterFailedLogin) immediately,
	// not after replica catch-up.
	user, err := s.repo.GetByEmailFromPrimary(ctx, email)
	if err != nil {
		// Burn a bcrypt comparison so the unknown-email path takes about as long as the
		// wrong-password path (prevents enumeration by timing), and return a generic
		// error that does not reveal whether the account exists.
		s.passwordService.DummyVerify(password)
		s.logger.Warn(ctx, "Login failed: user not found", "email", maskEmail(email))
		incMetric(s.metrics, metrics.CounterLoginFailure, "reason", "not_found")
		return nil, model.ErrInvalidCredentials
	}

	// Account enabled gate. Generic error + dummy compare so disabled is
	// indistinguishable from not-found/wrong-password.
	if !user.IsEnabled {
		s.passwordService.DummyVerify(password)
		s.logger.Warn(ctx, "Login failed: account disabled", "user_id", user.ID, "email", maskEmail(email))
		incMetric(s.metrics, metrics.CounterLoginFailure, "reason", "account_disabled")
		return nil, model.ErrInvalidCredentials
	}

	// Account locked gate (auto-unlock if locked_until has passed).
	if user.IsLocked {
		if user.LockedUntil != nil && time.Now().After(*user.LockedUntil) {
			if err := s.repo.Unlock(ctx, user.ID); err != nil {
				s.logger.Error(ctx, "Failed to auto-unlock account", "error", err.Error())
				incMetric(s.metrics, metrics.CounterBestEffortWriteFailure, "op", "auto_unlock")
				// Continue anyway - will try to authenticate.
			} else {
				s.logger.Info(ctx, "Account auto-unlocked", "user_id", user.ID)
				// Re-read from the PRIMARY: the unlock we just committed must be visible.
				user, err = s.repo.GetByIDFromPrimary(ctx, user.ID)
				if err != nil {
					return nil, sanitizeError(ctx, s.logger, "refresh user data", err)
				}
			}
		} else {
			s.passwordService.DummyVerify(password)
			s.logger.Warn(ctx, "Login failed: account locked", "user_id", user.ID, "locked_until", user.LockedUntil)
			incMetric(s.metrics, metrics.CounterLoginFailure, "reason", "account_locked")
			return nil, model.ErrInvalidCredentials
		}
	}

	// Verify password.
	if err := s.passwordService.VerifyPassword(password, user.PasswordHash); err != nil {
		s.logger.Warn(ctx, "Password verification failed", "user_id", user.ID, "email", maskEmail(email))

		// Record the failed attempt and lock at the threshold atomically in the DB.
		count, locked, regErr := s.repo.RegisterFailedLogin(ctx, user.ID, MaxFailedLoginAttempts, LockDuration)
		switch {
		case regErr != nil:
			s.logger.Error(ctx, "Failed to record failed login attempt", "error", regErr.Error())
			incMetric(s.metrics, metrics.CounterBestEffortWriteFailure, "op", "register_failed_login")
		case locked:
			s.logger.Warn(ctx, "Account locked after max failed attempts", "user_id", user.ID, "failed_attempts", count)
			incMetric(s.metrics, metrics.CounterAccountLockout)
		default:
			s.logger.Info(ctx, "Failed login attempt recorded", "user_id", user.ID, "failed_attempts", count)
		}

		incMetric(s.metrics, metrics.CounterLoginFailure, "reason", "bad_password")
		return nil, model.ErrInvalidCredentials
	}

	// Success: reset failed-login count (Unlock also clears the counter) and update
	// last_login. Both are best-effort — a failure here does not fail the login.
	if user.FailedLoginCount > 0 {
		if err := s.repo.Unlock(ctx, user.ID); err != nil {
			s.logger.Warn(ctx, "Failed to reset failed login count", "error", err.Error())
			incMetric(s.metrics, metrics.CounterBestEffortWriteFailure, "op", "reset_failed_count")
		}
	}
	if err := s.repo.UpdateLastLogin(ctx, user.ID); err != nil {
		s.logger.Warn(ctx, "Failed to update last login timestamp", "error", err.Error())
		incMetric(s.metrics, metrics.CounterBestEffortWriteFailure, "op", "update_last_login")
	}

	return user, nil
}

// Login authenticates a user into a known workspace (req.TenantID) with email and
// password, and returns a workspace-scoped access token plus an identity-session
// refresh token. Use LoginByEmail when the workspace is not known up front.
//
// Security note: the only built-in online-guessing defense is the per-account
// failed-login lockout. That bounds guessing against a single account but does NOT
// stop password spraying across many accounts or distributed guessing — the caller
// MUST apply IP/global rate limiting in front of Login. See SECURITY.md.
//
// Returns model.ErrInvalidCredentials on auth failure and model.ErrNoActiveMembership
// when the credentials are valid but the user has no active membership in req.TenantID.
func (s *AuthService) Login(ctx context.Context, req model.LoginRequest) (*model.LoginResponse, error) {
	email := normalizeEmail(req.Email)

	// Front-door rate limiting (caller-owned via Config.RateLimiter): keyed by tenant +
	// client IP when available, else tenant + email.
	rlKey := "login:" + req.TenantID + ":"
	if req.SessionInfo != nil && req.SessionInfo.IPAddress != "" {
		rlKey += req.SessionInfo.IPAddress
	} else {
		rlKey += "email:" + email
	}
	if err := checkRateLimit(ctx, s.rateLimiter, s.metrics, s.logger, rlKey); err != nil {
		return nil, err
	}

	s.logger.Debug(ctx, "User login attempt", "email", maskEmail(email), "tenant_id", req.TenantID)

	user, err := s.authenticateIdentity(ctx, email, req.Password)
	if err != nil {
		return nil, err
	}

	// Workspace gate: the identity must have an ACTIVE membership in req.TenantID.
	membership, err := s.activeMembership(ctx, user.ID, req.TenantID)
	if err != nil {
		if errors.Is(err, model.ErrNoActiveMembership) {
			incMetric(s.metrics, metrics.CounterLoginFailure, "reason", "no_membership")
		}
		return nil, err
	}

	// Mint the workspace-scoped access token + open the identity session.
	tokenPair, err := s.tokenService.GenerateTokenPair(ctx, user, membership, req.SessionInfo)
	if err != nil {
		s.logger.Error(ctx, "Failed to generate token pair", "error", err.Error())
		return nil, sanitizeError(ctx, s.logger, "generate tokens", err)
	}

	s.logger.Info(ctx, "User login successful", "user_id", user.ID, "email", maskEmail(email), "tenant_id", req.TenantID)
	incMetric(s.metrics, metrics.CounterLoginSuccess)

	return &model.LoginResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    tokenPair.ExpiresIn,
		User:         user,
		Memberships:  s.membershipList(ctx, user.ID, membership),
		TenantID:     req.TenantID,
	}, nil
}

// LoginByEmail authenticates the GLOBAL identity by email+password without a known
// workspace, opens the identity session (refresh token), and either mints a
// workspace-scoped access token (when req.TenantID is given, or the identity has
// exactly one active membership) or returns the membership list for the caller to
// choose from (then call MintWorkspaceToken). Memberships is always populated.
//
// Returns model.ErrInvalidCredentials on auth failure, and model.ErrNoActiveMembership
// when req.TenantID is given but is not one of the identity's active memberships.
func (s *AuthService) LoginByEmail(ctx context.Context, req model.LoginByEmailRequest) (*model.LoginResponse, error) {
	email := normalizeEmail(req.Email)

	rlKey := "login:"
	if req.SessionInfo != nil && req.SessionInfo.IPAddress != "" {
		rlKey += req.SessionInfo.IPAddress
	} else {
		rlKey += "email:" + email
	}
	if err := checkRateLimit(ctx, s.rateLimiter, s.metrics, s.logger, rlKey); err != nil {
		return nil, err
	}

	s.logger.Debug(ctx, "User login-by-email attempt", "email", maskEmail(email))

	user, err := s.authenticateIdentity(ctx, email, req.Password)
	if err != nil {
		return nil, err
	}

	// Load the identity's workspaces. Determine the active selection BEFORE opening the
	// session so an explicit-but-unauthorized workspace is rejected without minting a
	// (then-orphaned) refresh token.
	memberships, err := s.repo.ListMembershipsByUser(ctx, user.ID)
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "load memberships", err)
	}

	var selected *model.Membership
	if req.TenantID != "" {
		// Authorize the explicitly requested workspace against the PRIMARY (matching
		// Login / MintWorkspaceToken) so a just-committed revoke/suspend is observed
		// immediately and a token is never minted for a workspace the user just left.
		// The replica-sourced list above is informational only. A missing/suspended
		// membership surfaces as ErrNoActiveMembership.
		selected, err = s.activeMembership(ctx, user.ID, req.TenantID)
		if err != nil {
			return nil, err
		}
	} else {
		// No explicit workspace: auto-select iff the identity has exactly one active one.
		var active []*model.Membership
		for _, m := range memberships {
			if m.IsActive() {
				active = append(active, m)
			}
		}
		if len(active) == 1 {
			selected = active[0]
		}
	}

	// Open the identity session (refresh token) regardless of workspace selection.
	refreshToken, err := s.tokenService.CreateIdentitySession(ctx, user.ID, req.SessionInfo)
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "open identity session", err)
	}

	resp := &model.LoginResponse{
		RefreshToken: refreshToken,
		User:         user,
		Memberships:  membershipValues(memberships),
	}
	if selected != nil {
		accessToken, expiresIn, err := s.tokenService.MintAccessToken(ctx, user, selected)
		if err != nil {
			return nil, sanitizeError(ctx, s.logger, "mint access token", err)
		}
		resp.AccessToken = accessToken
		resp.ExpiresIn = expiresIn
		resp.TenantID = selected.TenantID
	}

	s.logger.Info(ctx, "User login-by-email successful", "user_id", user.ID, "workspace_selected", selected != nil)
	incMetric(s.metrics, metrics.CounterLoginSuccess)
	return resp, nil
}

// MintWorkspaceToken mints a fresh workspace-scoped access token for an existing
// identity session (the refresh token), for the user's active membership in tenantID.
// It is the select-workspace / switch-workspace call: the refresh token is NOT
// rotated. Returns model.ErrNoActiveMembership when the identity has no active
// membership in tenantID, and an invalid-refresh-token error when the session is bad
// or the account is inactive.
func (s *AuthService) MintWorkspaceToken(ctx context.Context, refreshToken, tenantID string) (*model.WorkspaceTokenResponse, error) {
	// Validate the identity session (this also gates disabled/locked accounts).
	user, err := s.tokenService.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	membership, err := s.activeMembership(ctx, user.ID, tenantID)
	if err != nil {
		return nil, err
	}

	accessToken, expiresIn, err := s.tokenService.MintAccessToken(ctx, user, membership)
	if err != nil {
		return nil, err
	}

	s.logger.Info(ctx, "Workspace token minted", "user_id", user.ID, "tenant_id", tenantID)
	return &model.WorkspaceTokenResponse{
		AccessToken: accessToken,
		ExpiresIn:   expiresIn,
		TenantID:    tenantID,
	}, nil
}

// activeMembership loads the (userID, tenantID) membership from the PRIMARY and
// returns it only when it exists and is active; otherwise it returns
// model.ErrNoActiveMembership (a missing or suspended membership) or a sanitized
// internal error. It backs the workspace gate in Login / MintWorkspaceToken.
func (s *AuthService) activeMembership(ctx context.Context, userID, tenantID string) (*model.Membership, error) {
	membership, err := s.repo.GetMembershipFromPrimary(ctx, userID, tenantID)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			s.logger.Warn(ctx, "No membership in tenant", "user_id", userID, "tenant_id", tenantID)
			return nil, model.ErrNoActiveMembership
		}
		return nil, sanitizeError(ctx, s.logger, "load membership", err)
	}
	if !membership.IsActive() {
		s.logger.Warn(ctx, "Membership not active", "user_id", userID, "tenant_id", tenantID)
		return nil, model.ErrNoActiveMembership
	}
	return membership, nil
}

// membershipList returns the user's memberships for a LoginResponse, falling back to
// just the known active membership if the (informational) list read fails — the login
// itself has already succeeded, so a list-read fault must not fail it.
func (s *AuthService) membershipList(ctx context.Context, userID string, fallback *model.Membership) []model.Membership {
	ms, err := s.repo.ListMembershipsByUser(ctx, userID)
	if err != nil {
		s.logger.Warn(ctx, "Failed to list memberships for login response", "user_id", userID, "error", err.Error())
		if fallback != nil {
			return []model.Membership{*fallback}
		}
		return nil
	}
	return membershipValues(ms)
}

// membershipValues dereferences a []*model.Membership into a []model.Membership for
// embedding in a response (never nil-element).
func membershipValues(ms []*model.Membership) []model.Membership {
	out := make([]model.Membership, 0, len(ms))
	for _, m := range ms {
		if m != nil {
			out = append(out, *m)
		}
	}
	return out
}

// Logout revokes a specific refresh token (single session logout). JWT access tokens
// remain valid until expiry (stateless design); for immediate revocation use
// LogoutAll, which bumps the identity token_version.
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	s.logger.Info(ctx, "User logout")

	if err := s.tokenService.RevokeRefreshToken(ctx, refreshToken); err != nil {
		s.logger.Error(ctx, "Failed to revoke refresh token", "error", err.Error())
		return sanitizeError(ctx, s.logger, "logout", err)
	}

	s.logger.Info(ctx, "User logged out successfully")
	return nil
}

// LogoutAll revokes all refresh tokens and invalidates all access tokens (every
// workspace) for an identity.
//
// Flow:
//  1. Increment the identity token_version. This invalidates every workspace's access
//     tokens; an unknown user id matches no row (ErrNotFound) and the operation fails
//     closed before any refresh token is touched.
//  2. Revoke all of the identity's refresh tokens.
//
// It is identity-level (decoupled model): there is no tenant scoping — a login is one
// identity session shared across the user's workspaces. The caller is responsible for
// authorizing that it may act on userID.
func (s *AuthService) LogoutAll(ctx context.Context, userID string) error {
	s.logger.Info(ctx, "Logout from all devices", "user_id", userID)

	if err := s.repo.IncrementTokenVersion(ctx, userID); err != nil {
		s.logger.Error(ctx, "Failed to increment token version", "error", err.Error())
		return sanitizeError(ctx, s.logger, "increment token version", err)
	}

	if err := s.tokenService.RevokeAllUserTokens(ctx, userID); err != nil {
		s.logger.Error(ctx, "Failed to revoke all refresh tokens", "error", err.Error())
		return sanitizeError(ctx, s.logger, "revoke refresh tokens", err)
	}

	s.logger.Info(ctx, "Logged out from all devices successfully", "user_id", userID)
	return nil
}

// RefreshToken rotates the identity-session refresh token and mints a new
// workspace-scoped access token for req.TenantID (token rotation + workspace scoping).
//
// Security note: like Login, RefreshToken has no built-in rate limiting; the caller
// should throttle it. Returns model.ErrNoActiveMembership when the identity no longer
// has an active membership in req.TenantID.
func (s *AuthService) RefreshToken(ctx context.Context, req model.RefreshRequest) (*model.RefreshResponse, error) {
	s.logger.Debug(ctx, "Refreshing tokens", "tenant_id", req.TenantID)

	rlKey := "refresh:"
	if req.SessionInfo != nil {
		rlKey += req.SessionInfo.IPAddress
	}
	if err := checkRateLimit(ctx, s.rateLimiter, s.metrics, s.logger, rlKey); err != nil {
		return nil, err
	}

	tokenPair, err := s.tokenService.RefreshTokenPair(ctx, req.RefreshToken, req.TenantID, req.SessionInfo)
	if err != nil {
		// ErrNoActiveMembership is a routine authorization outcome (the user left or was
		// removed from the workspace), not a fault — log it at Warn so it does not
		// pollute error dashboards or trip error-rate alerts. RefreshTokenPair has
		// already logged the specific reason.
		if errors.Is(err, model.ErrNoActiveMembership) {
			s.logger.Warn(ctx, "Refresh denied: no active membership in tenant", "tenant_id", req.TenantID)
		} else {
			s.logger.Error(ctx, "Failed to refresh token pair", "error", err.Error())
		}
		return nil, sanitizeError(ctx, s.logger, "refresh tokens", err)
	}

	// Extract the user/tenant from the freshly minted access token for the response.
	claims, err := s.jwtService.ValidateAccessToken(tokenPair.AccessToken)
	if err != nil {
		s.logger.Error(ctx, "Failed to validate new access token", "error", err.Error())
		return nil, sanitizeError(ctx, s.logger, "validate new token", err)
	}

	s.logger.Info(ctx, "Tokens refreshed successfully", "user_id", claims.UserID, "tenant_id", claims.TenantID)

	return &model.RefreshResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    tokenPair.ExpiresIn,
		UserID:       claims.UserID,
		TenantID:     claims.TenantID,
	}, nil
}

// ValidateJWT validates a workspace-scoped access token and checks both the identity
// and the membership it is scoped to.
//
// Flow (all DB reads from the PRIMARY — this is the revocation/account-status gate, so
// it must observe the latest writes rather than lagging a replica, which would fail
// open):
//  1. Validate JWT signature and expiration.
//  2. Load the identity; reject on identity token_version mismatch (ErrTokenRevoked),
//     disabled (ErrAccountDisabled), or locked (ErrAccountLocked, with auto-unlock).
//  3. Load the active membership for the token's tenant; reject when it is
//     missing/suspended or its token_version no longer matches (ErrTokenRevoked).
func (s *AuthService) ValidateJWT(ctx context.Context, token string) (*model.JWTClaims, error) {
	claims, err := s.jwtService.ValidateAccessToken(token)
	if err != nil {
		s.logger.Warn(ctx, "JWT validation failed", "error", err.Error())
		return nil, fmt.Errorf("invalid token: %w", model.ErrInvalidToken)
	}

	// --- Identity checks ---
	user, err := s.repo.GetByIDFromPrimary(ctx, claims.UserID)
	if err != nil {
		s.logger.Warn(ctx, "User not found for JWT", "user_id", claims.UserID, "error", err.Error())
		return nil, fmt.Errorf("user not found: %w", model.ErrInvalidToken)
	}
	if user.TokenVersion != claims.TokenVersion {
		s.logger.Warn(ctx, "Token version mismatch (identity)",
			"user_id", claims.UserID, "token_version", claims.TokenVersion, "current_version", user.TokenVersion)
		return nil, model.ErrTokenRevoked
	}
	if !user.IsEnabled {
		s.logger.Warn(ctx, "Account disabled", "user_id", claims.UserID)
		return nil, model.ErrAccountDisabled
	}
	if user.IsLocked {
		if user.LockedUntil != nil && time.Now().After(*user.LockedUntil) {
			if err := s.repo.Unlock(ctx, user.ID); err != nil {
				s.logger.Warn(ctx, "Failed to auto-unlock account", "error", err.Error())
				return nil, model.ErrAccountLocked
			}
			// Successfully unlocked, allow access.
		} else {
			s.logger.Warn(ctx, "Account locked", "user_id", claims.UserID)
			return nil, model.ErrAccountLocked
		}
	}

	// --- Membership checks (the token is workspace-scoped) ---
	membership, err := s.repo.GetMembershipFromPrimary(ctx, claims.UserID, claims.TenantID)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			s.logger.Warn(ctx, "Membership not found for JWT", "user_id", claims.UserID, "tenant_id", claims.TenantID)
			return nil, model.ErrTokenRevoked
		}
		return nil, sanitizeError(ctx, s.logger, "load membership", err)
	}
	if !membership.IsActive() {
		s.logger.Warn(ctx, "Membership not active for JWT", "user_id", claims.UserID, "tenant_id", claims.TenantID)
		return nil, model.ErrTokenRevoked
	}
	if membership.TokenVersion != claims.MembershipTokenVersion {
		s.logger.Warn(ctx, "Token version mismatch (membership)",
			"user_id", claims.UserID, "tenant_id", claims.TenantID,
			"token_version", claims.MembershipTokenVersion, "current_version", membership.TokenVersion)
		return nil, model.ErrTokenRevoked
	}

	s.logger.Debug(ctx, "JWT validated successfully", "user_id", claims.UserID, "tenant_id", claims.TenantID)
	return claims, nil
}

// ChangePassword changes a user's password and invalidates all sessions. It is
// identity-level (keyed by req.UserID only) — a credential is global.
//
// Flow:
//  1. Load the identity (from the primary).
//  2. Reject if the account is disabled or locked (incident-response freeze).
//  3. Verify the old password.
//  4. Validate new-password strength; hash it.
//  5. Atomically update the password AND bump the identity token_version (invalidate
//     every workspace's access tokens).
//  6. Revoke all refresh tokens (logout everywhere).
func (s *AuthService) ChangePassword(ctx context.Context, req model.ChangePasswordRequest) error {
	s.logger.Info(ctx, "Changing password", "user_id", req.UserID)

	user, err := s.repo.GetByIDFromPrimary(ctx, req.UserID)
	if err != nil {
		s.logger.Error(ctx, "Failed to load user for password change", "error", err.Error())
		return sanitizeError(ctx, s.logger, "retrieve user", err)
	}

	// Gate on account status: a disabled or locked account must not rotate its own
	// password mid-freeze, even with the correct old password.
	if !user.IsEnabled {
		s.logger.Warn(ctx, "Password change rejected: account disabled", "user_id", req.UserID)
		return model.ErrAccountDisabled
	}
	if isUserLocked(user) {
		s.logger.Warn(ctx, "Password change rejected: account locked", "user_id", req.UserID)
		return model.ErrAccountLocked
	}

	if err := s.passwordService.VerifyPassword(req.OldPassword, user.PasswordHash); err != nil {
		s.logger.Warn(ctx, "Old password verification failed", "user_id", req.UserID)
		return fmt.Errorf("incorrect old password: %w", model.ErrIncorrectPassword)
	}

	requirements := model.DefaultPasswordRequirements()
	if err := s.passwordService.ValidatePasswordStrength(req.NewPassword, requirements); err != nil {
		s.logger.Warn(ctx, "New password validation failed", "error", err.Error())
		return sanitizeError(ctx, s.logger, "validate password strength", err)
	}

	newHash, err := s.passwordService.HashPassword(req.NewPassword)
	if err != nil {
		s.logger.Error(ctx, "Failed to hash new password", "error", err.Error())
		return sanitizeError(ctx, s.logger, "hash password", err)
	}

	// Atomically update the password AND bump the identity token_version, so the change
	// can never be left half-applied.
	if err := s.repo.SetPasswordAndBumpTokenVersion(ctx, req.UserID, newHash); err != nil {
		s.logger.Error(ctx, "Failed to update password", "error", err.Error())
		return sanitizeError(ctx, s.logger, "update password", err)
	}

	// Revoke all refresh tokens so a leftover one cannot mint fresh access tokens
	// against the new password. Surfaced (not reported as success) on failure.
	if err := s.tokenService.RevokeAllUserTokens(ctx, req.UserID); err != nil {
		s.logger.Error(ctx, "Password updated but refresh-token revocation failed", "user_id", req.UserID, "error", err.Error())
		return sanitizeError(ctx, s.logger, "revoke existing sessions", err)
	}

	s.logger.Info(ctx, "Password changed successfully", "user_id", req.UserID)
	return nil
}
