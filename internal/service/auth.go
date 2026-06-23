// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
	"github.com/modgudinc/authkit-go/ratelimit"
)

// authRepository is the subset of the repository used by AuthService. Depending
// on an interface (rather than the concrete *repository.Repository) lets the
// security-critical auth logic be unit-tested with an in-memory fake.
type authRepository interface {
	GetByEmail(ctx context.Context, email, tenantID string) (*model.User, error)
	GetByEmailFromPrimary(ctx context.Context, email, tenantID string) (*model.User, error)
	GetByID(ctx context.Context, userID uuid.UUID, tenantID string) (*model.User, error)
	GetByIDFromPrimary(ctx context.Context, userID uuid.UUID, tenantID string) (*model.User, error)
	UnlockByTenant(ctx context.Context, userID uuid.UUID, tenantID string) error
	RegisterFailedLogin(ctx context.Context, userID uuid.UUID, maxAttempts int, lockDuration time.Duration) (int, bool, error)
	UpdateLastLoginByTenant(ctx context.Context, userID uuid.UUID, tenantID string) error
	VerifyPasswordByTenant(ctx context.Context, userID uuid.UUID, tenantID string) (string, error)
	SetPasswordByTenant(ctx context.Context, userID uuid.UUID, tenantID, hashedPassword string) error
	SetPasswordAndBumpTokenVersionByTenant(ctx context.Context, userID uuid.UUID, tenantID, hashedPassword string) error
	IncrementTokenVersionByTenant(ctx context.Context, userID uuid.UUID, tenantID string) error
}

// AuthService handles user authentication operations
// Integrates PasswordService, JWTService, and TokenService for complete auth flows
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

// Login authenticates a user with email and password
//
// Security note: the only built-in online-guessing defense is the per-account
// failed-login lockout (MaxFailedLoginAttempts, then a timed lock). That bounds
// guessing against a single account but does NOT stop password spraying across
// many accounts or distributed guessing — the caller MUST apply IP/global rate
// limiting in front of Login. See SECURITY.md ("Caller-Owned Controls").
//
// Parameters:
//   - ctx: Context for database operations
//   - req: Login request with email, password, tenant_id, and session info
//
// Returns:
//   - LoginResponse with tokens and user info
//   - Error if authentication fails
//
// Flow:
//  1. Get user by email + tenant
//  2. Check account is enabled (not disabled by admin)
//  3. Check account is not locked (auto-unlock if locked_until has passed)
//  4. Verify password with PasswordService
//  5. On failure: increment failed_login_count, lock if >= 5 attempts
//  6. On success: reset failed_login_count, update last_login
//  7. Generate token pair with TokenService
//  8. Return LoginResponse
//
// Example:
//
//	response, err := authService.Login(ctx, LoginRequest{
//	    Email:    "user@acme.com",
//	    Password: "SecurePassword123!",
//	    TenantID: "acme.com",
//	    SessionInfo: &model.SessionInfo{
//	        IPAddress:  "192.168.1.1",
//	        UserAgent:  "Mozilla/5.0...",
//	        DeviceName: "Chrome Browser",
//	    },
//	})
func (s *AuthService) Login(ctx context.Context, req model.LoginRequest) (*model.LoginResponse, error) {
	// Normalize the email so lookups match how users are stored (see normalizeEmail).
	email := normalizeEmail(req.Email)

	// Front-door rate limiting (caller-owned via Config.RateLimiter): keyed by tenant
	// + client IP when available, else tenant + email, so a configured limiter can
	// throttle the spraying/distributed guessing the per-account lockout does not stop.
	rlKey := "login:" + req.TenantID + ":"
	if req.SessionInfo != nil && req.SessionInfo.IPAddress != "" {
		rlKey += req.SessionInfo.IPAddress
	} else {
		rlKey += "email:" + email
	}
	if err := checkRateLimit(ctx, s.rateLimiter, s.metrics, s.logger, rlKey); err != nil {
		return nil, err
	}

	// Per-attempt line is high-volume; log at Debug (success/lockout are logged below).
	s.logger.Debug(ctx, "User login attempt",
		"email", maskEmail(email),
		"tenant_id", req.TenantID,
	)

	// 1. Get user by email + tenant. Read from the PRIMARY: the is_enabled/is_locked
	// gate below must observe an admin disable/lock (or an auto-lock just written by
	// RegisterFailedLogin) immediately, not after replica catch-up.
	user, err := s.repo.GetByEmailFromPrimary(ctx, email, req.TenantID)
	if err != nil {
		// Burn a bcrypt comparison so the unknown-email path takes about as long
		// as the wrong-password path (prevents username enumeration by timing),
		// and return a generic error that does not reveal whether the account exists.
		s.passwordService.DummyVerify(req.Password)
		// Do not log err.Error() here: it can echo lookup/query context and,
		// together with the email, turns this line into an account-enumeration
		// list. The generic ErrInvalidCredentials is what callers receive.
		s.logger.Warn(ctx, "Login failed: user not found",
			"email", maskEmail(email),
			"tenant_id", req.TenantID,
		)
		incMetric(s.metrics, metrics.CounterLoginFailure, "reason", "not_found")
		return nil, model.ErrInvalidCredentials
	}

	// 2. Check account is enabled. Returned as a generic error (the specific
	// reason is logged) so the client cannot distinguish disabled from
	// not-found/wrong-password; equalize timing with a dummy bcrypt compare.
	if !user.IsEnabled {
		s.passwordService.DummyVerify(req.Password)
		s.logger.Warn(ctx, "Login failed: account disabled",
			"user_id", user.ID.String(),
			"email", maskEmail(email),
		)
		incMetric(s.metrics, metrics.CounterLoginFailure, "reason", "account_disabled")
		return nil, model.ErrInvalidCredentials
	}

	// 3. Check account is not locked (or auto-unlock if locked_until has passed)
	if user.IsLocked {
		if user.LockedUntil != nil && time.Now().After(*user.LockedUntil) {
			// Auto-unlock: locked_until has passed
			if err := s.repo.UnlockByTenant(ctx, user.ID, req.TenantID); err != nil {
				s.logger.Error(ctx, "Failed to auto-unlock account", "error", err.Error())
				incMetric(s.metrics, metrics.CounterBestEffortWriteFailure, "op", "auto_unlock")
				// Continue anyway - will try to authenticate
			} else {
				s.logger.Info(ctx, "Account auto-unlocked", "user_id", user.ID.String())
				// Refresh user data from the PRIMARY: the unlock we just committed
				// (UnlockByTenant writes rw) must be visible here, so re-reading from a
				// lagging replica could still show the account locked.
				user, err = s.repo.GetByIDFromPrimary(ctx, user.ID, req.TenantID)
				if err != nil {
					return nil, sanitizeError(ctx, s.logger, "refresh user data", err)
				}
			}
		} else {
			// Still locked. Generic error + dummy compare so a locked account is
			// indistinguishable (by message or timing) from not-found/wrong-password.
			s.passwordService.DummyVerify(req.Password)
			s.logger.Warn(ctx, "Login failed: account locked",
				"user_id", user.ID.String(),
				"locked_until", user.LockedUntil,
			)
			incMetric(s.metrics, metrics.CounterLoginFailure, "reason", "account_locked")
			return nil, model.ErrInvalidCredentials
		}
	}

	// 4. Verify password
	err = s.passwordService.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil {
		// Password verification failed
		s.logger.Warn(ctx, "Password verification failed",
			"user_id", user.ID.String(),
			"email", maskEmail(email),
		)

		// Record the failed attempt and lock at the threshold atomically in the DB.
		// The lock decision uses the authoritative post-increment count returned by
		// the UPDATE, not the (possibly stale) count loaded at the start of this
		// request, so concurrent failures can't trip the lock one attempt early/late.
		count, locked, regErr := s.repo.RegisterFailedLogin(ctx, user.ID, MaxFailedLoginAttempts, LockDuration)
		switch {
		case regErr != nil:
			s.logger.Error(ctx, "Failed to record failed login attempt", "error", regErr.Error())
			incMetric(s.metrics, metrics.CounterBestEffortWriteFailure, "op", "register_failed_login")
			// Continue anyway - authentication still failed.
		case locked:
			s.logger.Warn(ctx, "Account locked after max failed attempts",
				"user_id", user.ID.String(),
				"failed_attempts", count,
			)
			incMetric(s.metrics, metrics.CounterAccountLockout)
		default:
			s.logger.Info(ctx, "Failed login attempt recorded",
				"user_id", user.ID.String(),
				"failed_attempts", count,
			)
		}

		incMetric(s.metrics, metrics.CounterLoginFailure, "reason", "bad_password")
		return nil, model.ErrInvalidCredentials
	}

	// 5. Password verification succeeded
	// Reset failed login count if any
	if user.FailedLoginCount > 0 {
		if err := s.repo.UnlockByTenant(ctx, user.ID, req.TenantID); err != nil {
			s.logger.Warn(ctx, "Failed to reset failed login count", "error", err.Error())
			incMetric(s.metrics, metrics.CounterBestEffortWriteFailure, "op", "reset_failed_count")
			// Continue anyway - user authenticated successfully
		}
	}

	// 6. Update last login timestamp
	if err := s.repo.UpdateLastLoginByTenant(ctx, user.ID, req.TenantID); err != nil {
		s.logger.Warn(ctx, "Failed to update last login timestamp", "error", err.Error())
		incMetric(s.metrics, metrics.CounterBestEffortWriteFailure, "op", "update_last_login")
		// Continue anyway - non-critical operation
	}

	// 7. Generate token pair
	tokenPair, err := s.tokenService.GenerateTokenPair(ctx, user, req.SessionInfo)
	if err != nil {
		s.logger.Error(ctx, "Failed to generate token pair", "error", err.Error())
		return nil, sanitizeError(ctx, s.logger, "generate tokens", err)
	}

	s.logger.Info(ctx, "User login successful",
		"user_id", user.ID.String(),
		"email", maskEmail(email),
		"tenant_id", req.TenantID,
	)
	incMetric(s.metrics, metrics.CounterLoginSuccess)

	// 8. Return LoginResponse
	return &model.LoginResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    tokenPair.ExpiresIn,
		User:         user,
	}, nil
}

// Logout revokes a specific refresh token (single session logout)
//
// Parameters:
//   - ctx: Context for database operations
//   - refreshToken: Refresh token to revoke
//
// Note: JWT access tokens remain valid until expiry (stateless design)
// For immediate revocation, use LogoutAll() which increments token_version
//
// Example:
//
//	err := authService.Logout(ctx, refreshToken)
//	if err != nil {
//	    return fmt.Errorf("logout failed: %w", err)
//	}
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	s.logger.Info(ctx, "User logout")

	if err := s.tokenService.RevokeRefreshToken(ctx, refreshToken); err != nil {
		s.logger.Error(ctx, "Failed to revoke refresh token", "error", err.Error())
		return sanitizeError(ctx, s.logger, "logout", err)
	}

	s.logger.Info(ctx, "User logged out successfully")

	return nil
}

// LogoutAll revokes all refresh tokens and invalidates all JWTs for a user
//
// Parameters:
//   - ctx: Context for database operations
//   - userID: User UUID
//   - tenantID: Tenant the user must belong to (enforced — see below)
//
// Flow:
//  1. Increment token_version scoped to (userID, tenantID). This both invalidates
//     all existing JWTs AND validates tenant ownership: a userID that does not
//     belong to tenantID matches no row and returns ErrNotFound, so the operation
//     fails closed before any refresh token is touched.
//  2. Revoke all refresh tokens for the user.
//
// Use cases:
//   - "Logout from all devices" functionality
//   - Security breach response
//   - Password reset
//
// Tenant isolation: this method is scoped by tenantID, so a caller-supplied userID
// from another tenant is rejected rather than silently logging out an unrelated
// account. Pass the tenant the caller is authorized for.
//
// Example:
//
//	err := authService.LogoutAll(ctx, userID, tenantID)
//	if err != nil {
//	    return fmt.Errorf("logout all failed: %w", err)
//	}
func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID, tenantID string) error {
	s.logger.Info(ctx, "Logout from all devices", "user_id", userID, "tenant_id", tenantID)

	// 1. Increment token version (invalidates all JWTs) scoped to the tenant. This
	// also gates the whole operation on tenant ownership: a cross-tenant userID
	// matches no row (ErrNotFound) and we stop here without revoking any tokens.
	if err := s.repo.IncrementTokenVersionByTenant(ctx, userID, tenantID); err != nil {
		s.logger.Error(ctx, "Failed to increment token version", "error", err.Error())
		return sanitizeError(ctx, s.logger, "increment token version", err)
	}

	// 2. Revoke all refresh tokens (refresh tokens are keyed by user_id and carry
	// no tenant column; step 1 has already proven the user belongs to the tenant).
	if err := s.tokenService.RevokeAllUserTokens(ctx, userID); err != nil {
		s.logger.Error(ctx, "Failed to revoke all refresh tokens", "error", err.Error())
		return sanitizeError(ctx, s.logger, "revoke refresh tokens", err)
	}

	s.logger.Info(ctx, "Logged out from all devices successfully", "user_id", userID, "tenant_id", tenantID)

	return nil
}

// RefreshToken validates refresh token and returns new token pair (token rotation)
//
// Security note: like Login, RefreshToken has no built-in rate limiting. Refresh
// tokens are 256-bit random and not feasibly guessable, but the caller should
// still throttle this endpoint to bound abuse. See SECURITY.md ("Caller-Owned
// Controls").
//
// Parameters:
//   - ctx: Context for database operations
//   - req: Refresh request with refresh token and session info
//
// Returns:
//   - RefreshResponse with new access token and new refresh token
//   - Error if refresh token is invalid or expired
//
// Flow:
//  1. Validate refresh token via TokenService
//  2. Rotate tokens (old token revoked, new tokens generated)
//  3. Return new token pair
//
// Example:
//
//	response, err := authService.RefreshToken(ctx, RefreshRequest{
//	    RefreshToken: oldRefreshToken,
//	    SessionInfo:  sessionInfo,
//	})
//	if err != nil {
//	    return fmt.Errorf("token refresh failed: %w", err)
//	}
//	// Return new tokens to client
func (s *AuthService) RefreshToken(ctx context.Context, req model.RefreshRequest) (*model.RefreshResponse, error) {
	s.logger.Debug(ctx, "Refreshing tokens")

	// Front-door rate limiting (caller-owned via Config.RateLimiter): refresh has no
	// tenant/account context before the token is validated, so key by client IP when
	// available. A configured limiter throttles refresh abuse, which has no per-account
	// lockout of its own.
	rlKey := "refresh:"
	if req.SessionInfo != nil {
		rlKey += req.SessionInfo.IPAddress
	}
	if err := checkRateLimit(ctx, s.rateLimiter, s.metrics, s.logger, rlKey); err != nil {
		return nil, err
	}

	// Rotate tokens via TokenService
	tokenPair, err := s.tokenService.RefreshTokenPair(ctx, req.RefreshToken, req.SessionInfo)
	if err != nil {
		s.logger.Error(ctx, "Failed to refresh token pair", "error", err.Error())
		return nil, sanitizeError(ctx, s.logger, "refresh tokens", err)
	}

	// Get user ID from new access token
	claims, err := s.jwtService.ValidateAccessToken(tokenPair.AccessToken)
	if err != nil {
		s.logger.Error(ctx, "Failed to validate new access token", "error", err.Error())
		return nil, sanitizeError(ctx, s.logger, "validate new token", err)
	}

	s.logger.Info(ctx, "Tokens refreshed successfully", "user_id", claims.UserID)

	return &model.RefreshResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    tokenPair.ExpiresIn,
		UserID:       claims.UserID,
	}, nil
}

// ValidateJWT validates a JWT access token and checks user account status
//
// Parameters:
//   - ctx: Context for database operations
//   - token: JWT access token string
//
// Returns:
//   - JWTClaims if token is valid and user account is active
//   - Error if token is invalid, expired, or user account is disabled/locked
//
// Flow:
//  1. Validate JWT signature and expiration via JWTService
//  2. Get user from database
//  3. Check token_version matches (detect invalidated tokens)
//  4. Check account is enabled and not locked
//  5. Return claims
//
// Example:
//
//	claims, err := authService.ValidateJWT(ctx, tokenString)
//	if err != nil {
//	    return fmt.Errorf("unauthorized: %w", err)
//	}
//	// Use claims.UserID, claims.TenantID, claims.Roles
func (s *AuthService) ValidateJWT(ctx context.Context, token string) (*model.JWTClaims, error) {
	// 1. Validate JWT signature and expiration
	claims, err := s.jwtService.ValidateAccessToken(token)
	if err != nil {
		s.logger.Warn(ctx, "JWT validation failed", "error", err.Error())
		return nil, fmt.Errorf("invalid token: %w", model.ErrInvalidToken)
	}

	// 2. Get user from database (claims.UserID is a uuid.UUID; a malformed token
	// id would already have failed JWT claim parsing above). Read from the PRIMARY:
	// this is the revocation/account-status gate, so token_version, is_enabled and
	// is_locked must reflect LogoutAll / ChangePassword / disable / lock writes
	// immediately rather than lagging a read replica (which would fail open).
	user, err := s.repo.GetByIDFromPrimary(ctx, claims.UserID, claims.TenantID)
	if err != nil {
		s.logger.Warn(ctx, "User not found for JWT", "user_id", claims.UserID, "error", err.Error())
		return nil, fmt.Errorf("user not found: %w", model.ErrInvalidToken)
	}

	// 3. Check token_version matches (detect revoked tokens)
	if user.TokenVersion != claims.TokenVersion {
		s.logger.Warn(ctx, "Token version mismatch",
			"user_id", claims.UserID,
			"token_version", claims.TokenVersion,
			"current_version", user.TokenVersion,
		)
		return nil, model.ErrTokenRevoked
	}

	// 4. Check account is enabled
	if !user.IsEnabled {
		s.logger.Warn(ctx, "Account disabled", "user_id", claims.UserID)
		return nil, model.ErrAccountDisabled
	}

	// 5. Check account is not locked (or auto-unlock if locked_until has passed)
	if user.IsLocked {
		if user.LockedUntil != nil && time.Now().After(*user.LockedUntil) {
			// Auto-unlock
			if err := s.repo.UnlockByTenant(ctx, user.ID, claims.TenantID); err != nil {
				s.logger.Warn(ctx, "Failed to auto-unlock account", "error", err.Error())
				// Still return locked error
				return nil, model.ErrAccountLocked
			}
			// Successfully unlocked, allow access
		} else {
			s.logger.Warn(ctx, "Account locked", "user_id", claims.UserID)
			return nil, model.ErrAccountLocked
		}
	}

	// Per-request success line is high-volume (every authenticated request); Debug.
	s.logger.Debug(ctx, "JWT validated successfully", "user_id", claims.UserID)

	return claims, nil
}

// ChangePassword changes a user's password and invalidates all sessions
//
// Parameters:
//   - ctx: Context for database operations
//   - req: Change password request with user_id, old password, new password
//
// Returns:
//   - Error if password change fails
//
// Flow:
//  1. Load the user (tenant-scoped, from the primary)
//  2. Reject if the account is disabled or locked (incident-response freeze)
//  3. Verify old password
//  4. Validate new password strength
//  5. Hash new password
//  6. Atomically update the password AND bump token_version (invalidate all JWTs)
//  7. Revoke all refresh tokens (logout from all devices)
//
// Example:
//
//	err := authService.ChangePassword(ctx, ChangePasswordRequest{
//	    UserID:      userID,
//	    TenantID:    tenantID,
//	    OldPassword: "OldPassword123!",
//	    NewPassword: "NewSecurePassword456!",
//	})
//	if err != nil {
//	    return fmt.Errorf("password change failed: %w", err)
//	}
func (s *AuthService) ChangePassword(ctx context.Context, req model.ChangePasswordRequest) error {
	s.logger.Info(ctx, "Changing password", "user_id", req.UserID)

	// 1. Load the user, scoped to the tenant so a caller-supplied user id from
	// another tenant cannot be targeted (returns ErrNotFound on mismatch). Read from
	// the PRIMARY so a just-committed disable/lock is observed by the status gate
	// below rather than lagging a read replica.
	user, err := s.repo.GetByIDFromPrimary(ctx, req.UserID, req.TenantID)
	if err != nil {
		s.logger.Error(ctx, "Failed to load user for password change", "error", err.Error())
		return sanitizeError(ctx, s.logger, "retrieve user", err)
	}

	// 2. Gate on account status. A disabled or locked account must not be able to
	// rotate its own password mid-freeze (e.g. during incident response), even with
	// the correct old password — mirroring the Login and ValidateJWT gates. Login
	// still rejects these accounts, so this is account-freeze completeness, not an
	// auth bypass. A lock whose locked_until has elapsed is treated as expired (see
	// isUserLocked), so a stale lock does not permanently block a legitimate change.
	if !user.IsEnabled {
		s.logger.Warn(ctx, "Password change rejected: account disabled", "user_id", req.UserID)
		return model.ErrAccountDisabled
	}
	if isUserLocked(user) {
		s.logger.Warn(ctx, "Password change rejected: account locked", "user_id", req.UserID)
		return model.ErrAccountLocked
	}

	// 3. Verify old password against the loaded hash.
	if err := s.passwordService.VerifyPassword(req.OldPassword, user.PasswordHash); err != nil {
		s.logger.Warn(ctx, "Old password verification failed", "user_id", req.UserID)
		return fmt.Errorf("incorrect old password: %w", model.ErrIncorrectPassword)
	}

	// 4. Validate new password strength (optional - can be disabled if not needed)
	requirements := model.DefaultPasswordRequirements()
	err = s.passwordService.ValidatePasswordStrength(req.NewPassword, requirements)
	if err != nil {
		s.logger.Warn(ctx, "New password validation failed", "error", err.Error())
		return sanitizeError(ctx, s.logger, "validate password strength", err)
	}

	// 5. Hash new password
	newHash, err := s.passwordService.HashPassword(req.NewPassword)
	if err != nil {
		s.logger.Error(ctx, "Failed to hash new password", "error", err.Error())
		return sanitizeError(ctx, s.logger, "hash password", err)
	}

	// 6. Atomically update the password AND bump token_version in a single
	// tenant-scoped UPDATE. Doing both at once means the change can never be left
	// half-applied — there is no window where the password is changed but old access
	// tokens (<=15m) still validate, or vice versa.
	if err := s.repo.SetPasswordAndBumpTokenVersionByTenant(ctx, req.UserID, req.TenantID, newHash); err != nil {
		s.logger.Error(ctx, "Failed to update password", "error", err.Error())
		return sanitizeError(ctx, s.logger, "update password", err)
	}

	// 7. Revoke all refresh tokens. The password change and JWT invalidation are
	// already durably committed by step 6; this removes the refresh tokens so a
	// leftover one cannot mint fresh access tokens against the new password. It is a
	// follow-up step rather than part of the atomic write, but its failure is still
	// surfaced (NOT reported as success), since an undeleted refresh token stays
	// usable for up to RefreshExpiry. On failure the caller should retry revocation
	// via LogoutAll — re-running ChangePassword will not work because the old
	// password no longer verifies. Tenant ownership was already proven in step 1
	// (VerifyPasswordByTenant), so revoking by user_id here is safe.
	if err := s.tokenService.RevokeAllUserTokens(ctx, req.UserID); err != nil {
		s.logger.Error(ctx, "Password updated but refresh-token revocation failed", "user_id", req.UserID, "error", err.Error())
		return sanitizeError(ctx, s.logger, "revoke existing sessions", err)
	}

	s.logger.Info(ctx, "Password changed successfully", "user_id", req.UserID)

	return nil
}
