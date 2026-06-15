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
	"github.com/modgudinc/authkit-go/model"
)

// authRepository is the subset of the repository used by AuthService. Depending
// on an interface (rather than the concrete *repository.Repository) lets the
// security-critical auth logic be unit-tested with an in-memory fake.
type authRepository interface {
	GetByEmail(ctx context.Context, email, tenantID string) (*model.User, error)
	GetByID(ctx context.Context, userID uuid.UUID, tenantID string) (*model.User, error)
	Lock(ctx context.Context, userID uuid.UUID, lockedUntil *time.Time) error
	Unlock(ctx context.Context, userID uuid.UUID) error
	IncrementFailedLoginCount(ctx context.Context, userID uuid.UUID) error
	RegisterFailedLogin(ctx context.Context, userID uuid.UUID, maxAttempts int, lockDuration time.Duration) (int, bool, error)
	UpdateLastLogin(ctx context.Context, userID uuid.UUID) error
	VerifyPassword(ctx context.Context, userID uuid.UUID) (string, error)
	SetPassword(ctx context.Context, userID uuid.UUID, hashedPassword string) error
	IncrementTokenVersion(ctx context.Context, userID uuid.UUID) error
}

// AuthService handles user authentication operations
// Integrates PasswordService, JWTService, and TokenService for complete auth flows
type AuthService struct {
	repo            authRepository
	passwordService *PasswordService
	tokenService    *TokenService
	jwtService      *JWTService
	logger          logger.Logger
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
func NewAuthService(
	repo *repository.Repository,
	passwordService *PasswordService,
	tokenService *TokenService,
	jwtService *JWTService,
	logger logger.Logger,
) *AuthService {
	return &AuthService{
		repo:            repo,
		passwordService: passwordService,
		tokenService:    tokenService,
		jwtService:      jwtService,
		logger:          logger,
	}
}

// Login authenticates a user with email and password
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

	if s.logger != nil {
		s.logger.Info("User login attempt",
			"email", maskEmail(email),
			"tenant_id", req.TenantID,
		)
	}

	// 1. Get user by email + tenant
	user, err := s.repo.GetByEmail(ctx, email, req.TenantID)
	if err != nil {
		// Burn a bcrypt comparison so the unknown-email path takes about as long
		// as the wrong-password path (prevents username enumeration by timing),
		// and return a generic error that does not reveal whether the account exists.
		s.passwordService.DummyVerify(req.Password)
		if s.logger != nil {
			// Do not log err.Error() here: it can echo lookup/query context and,
			// together with the email, turns this line into an account-enumeration
			// list. The generic ErrInvalidCredentials is what callers receive.
			s.logger.Warn("Login failed: user not found",
				"email", maskEmail(email),
				"tenant_id", req.TenantID,
			)
		}
		return nil, model.ErrInvalidCredentials
	}

	// 2. Check account is enabled. Returned as a generic error (the specific
	// reason is logged) so the client cannot distinguish disabled from
	// not-found/wrong-password; equalize timing with a dummy bcrypt compare.
	if !user.IsEnabled {
		s.passwordService.DummyVerify(req.Password)
		if s.logger != nil {
			s.logger.Warn("Login failed: account disabled",
				"user_id", user.ID.String(),
				"email", maskEmail(req.Email),
			)
		}
		return nil, model.ErrInvalidCredentials
	}

	// 3. Check account is not locked (or auto-unlock if locked_until has passed)
	if user.IsLocked {
		if user.LockedUntil != nil && time.Now().After(*user.LockedUntil) {
			// Auto-unlock: locked_until has passed
			if err := s.repo.Unlock(ctx, user.ID); err != nil {
				if s.logger != nil {
					s.logger.Error("Failed to auto-unlock account", "error", err.Error())
				}
				// Continue anyway - will try to authenticate
			} else {
				if s.logger != nil {
					s.logger.Info("Account auto-unlocked", "user_id", user.ID.String())
				}
				// Refresh user data
				user, err = s.repo.GetByID(ctx, user.ID, req.TenantID)
				if err != nil {
					return nil, fmt.Errorf("failed to refresh user data: %w", err)
				}
			}
		} else {
			// Still locked. Generic error + dummy compare so a locked account is
			// indistinguishable (by message or timing) from not-found/wrong-password.
			s.passwordService.DummyVerify(req.Password)
			if s.logger != nil {
				s.logger.Warn("Login failed: account locked",
					"user_id", user.ID.String(),
					"locked_until", user.LockedUntil,
				)
			}
			return nil, model.ErrInvalidCredentials
		}
	}

	// 4. Verify password
	err = s.passwordService.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil {
		// Password verification failed
		if s.logger != nil {
			s.logger.Warn("Password verification failed",
				"user_id", user.ID.String(),
				"email", maskEmail(req.Email),
			)
		}

		// Record the failed attempt and lock at the threshold atomically in the DB.
		// The lock decision uses the authoritative post-increment count returned by
		// the UPDATE, not the (possibly stale) count loaded at the start of this
		// request, so concurrent failures can't trip the lock one attempt early/late.
		count, locked, regErr := s.repo.RegisterFailedLogin(ctx, user.ID, MaxFailedLoginAttempts, LockDuration)
		switch {
		case regErr != nil:
			if s.logger != nil {
				s.logger.Error("Failed to record failed login attempt", "error", regErr.Error())
			}
			// Continue anyway - authentication still failed.
		case locked:
			if s.logger != nil {
				s.logger.Warn("Account locked after max failed attempts",
					"user_id", user.ID.String(),
					"failed_attempts", count,
				)
			}
		default:
			if s.logger != nil {
				s.logger.Info("Failed login attempt recorded",
					"user_id", user.ID.String(),
					"failed_attempts", count,
				)
			}
		}

		return nil, model.ErrInvalidCredentials
	}

	// 5. Password verification succeeded
	// Reset failed login count if any
	if user.FailedLoginCount > 0 {
		if err := s.repo.Unlock(ctx, user.ID); err != nil {
			if s.logger != nil {
				s.logger.Warn("Failed to reset failed login count", "error", err.Error())
			}
			// Continue anyway - user authenticated successfully
		}
	}

	// 6. Update last login timestamp
	if err := s.repo.UpdateLastLogin(ctx, user.ID); err != nil {
		if s.logger != nil {
			s.logger.Warn("Failed to update last login timestamp", "error", err.Error())
		}
		// Continue anyway - non-critical operation
	}

	// 7. Generate token pair
	tokenPair, err := s.tokenService.GenerateTokenPair(ctx, user, req.SessionInfo)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to generate token pair", "error", err.Error())
		}
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("User login successful",
			"user_id", user.ID.String(),
			"email", maskEmail(req.Email),
			"tenant_id", req.TenantID,
		)
	}

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
	if s.logger != nil {
		s.logger.Info("User logout")
	}

	if err := s.tokenService.RevokeRefreshToken(ctx, refreshToken); err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to revoke refresh token", "error", err.Error())
		}
		return fmt.Errorf("logout failed: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("User logged out successfully")
	}

	return nil
}

// LogoutAll revokes all refresh tokens and invalidates all JWTs for a user
//
// Parameters:
//   - ctx: Context for database operations
//   - userID: User UUID string
//
// Flow:
//  1. Revoke all refresh tokens
//  2. Increment token_version (invalidates all existing JWTs)
//
// Use cases:
//   - "Logout from all devices" functionality
//   - Security breach response
//   - Password reset
//
// Precondition: the caller MUST have already verified that userID belongs to the
// caller's tenant. This method acts on a caller-supplied user id and does not
// re-check tenant membership, so authorize the id before calling it.
//
// Example:
//
//	err := authService.LogoutAll(ctx, userID)
//	if err != nil {
//	    return fmt.Errorf("logout all failed: %w", err)
//	}
func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	if s.logger != nil {
		s.logger.Info("Logout from all devices", "user_id", userID)
	}

	// 1. Revoke all refresh tokens
	if err := s.tokenService.RevokeAllUserTokens(ctx, userID); err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to revoke all refresh tokens", "error", err.Error())
		}
		return fmt.Errorf("failed to revoke refresh tokens: %w", err)
	}

	// 2. Increment token version (invalidates all JWTs)
	if err := s.repo.IncrementTokenVersion(ctx, userID); err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to increment token version", "error", err.Error())
		}
		return fmt.Errorf("failed to increment token version: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("Logged out from all devices successfully", "user_id", userID)
	}

	return nil
}

// RefreshToken validates refresh token and returns new token pair (token rotation)
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
	if s.logger != nil {
		s.logger.Info("Refreshing tokens")
	}

	// Rotate tokens via TokenService
	tokenPair, err := s.tokenService.RefreshTokenPair(ctx, req.RefreshToken, req.SessionInfo)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to refresh token pair", "error", err.Error())
		}
		return nil, fmt.Errorf("failed to refresh tokens: %w", err)
	}

	// Get user ID from new access token
	claims, err := s.jwtService.ValidateAccessToken(tokenPair.AccessToken)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to validate new access token", "error", err.Error())
		}
		return nil, fmt.Errorf("failed to validate new token: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("Tokens refreshed successfully", "user_id", claims.UserID)
	}

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
		if s.logger != nil {
			s.logger.Warn("JWT validation failed", "error", err.Error())
		}
		return nil, fmt.Errorf("invalid token: %w", model.ErrInvalidToken)
	}

	// 2. Get user from database (claims.UserID is a uuid.UUID; a malformed token
	// id would already have failed JWT claim parsing above).
	user, err := s.repo.GetByID(ctx, claims.UserID, claims.TenantID)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("User not found for JWT", "user_id", claims.UserID, "error", err.Error())
		}
		return nil, fmt.Errorf("user not found: %w", model.ErrInvalidToken)
	}

	// 3. Check token_version matches (detect revoked tokens)
	if user.TokenVersion != claims.TokenVersion {
		if s.logger != nil {
			s.logger.Warn("Token version mismatch",
				"user_id", claims.UserID,
				"token_version", claims.TokenVersion,
				"current_version", user.TokenVersion,
			)
		}
		return nil, model.ErrTokenRevoked
	}

	// 4. Check account is enabled
	if !user.IsEnabled {
		if s.logger != nil {
			s.logger.Warn("Account disabled", "user_id", claims.UserID)
		}
		return nil, model.ErrAccountDisabled
	}

	// 5. Check account is not locked (or auto-unlock if locked_until has passed)
	if user.IsLocked {
		if user.LockedUntil != nil && time.Now().After(*user.LockedUntil) {
			// Auto-unlock
			if err := s.repo.Unlock(ctx, user.ID); err != nil {
				if s.logger != nil {
					s.logger.Warn("Failed to auto-unlock account", "error", err.Error())
				}
				// Still return locked error
				return nil, model.ErrAccountLocked
			}
			// Successfully unlocked, allow access
		} else {
			if s.logger != nil {
				s.logger.Warn("Account locked", "user_id", claims.UserID)
			}
			return nil, model.ErrAccountLocked
		}
	}

	if s.logger != nil {
		s.logger.Info("JWT validated successfully", "user_id", claims.UserID)
	}

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
//  1. Get user by ID
//  2. Verify old password
//  3. Validate new password strength (optional)
//  4. Hash new password
//  5. Update password in database
//  6. Increment token_version (invalidate all JWTs)
//  7. Revoke all refresh tokens (logout from all devices)
//
// Example:
//
//	err := authService.ChangePassword(ctx, ChangePasswordRequest{
//	    UserID:      userID,
//	    OldPassword: "OldPassword123!",
//	    NewPassword: "NewSecurePassword456!",
//	})
//	if err != nil {
//	    return fmt.Errorf("password change failed: %w", err)
//	}
func (s *AuthService) ChangePassword(ctx context.Context, req model.ChangePasswordRequest) error {
	if s.logger != nil {
		s.logger.Info("Changing password", "user_id", req.UserID)
	}

	// 1. Get current password hash (req.UserID is a uuid.UUID).
	currentHash, err := s.repo.VerifyPassword(ctx, req.UserID)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to get current password hash", "error", err.Error())
		}
		return fmt.Errorf("failed to retrieve user password: %w", err)
	}

	// 2. Verify old password
	err = s.passwordService.VerifyPassword(req.OldPassword, currentHash)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("Old password verification failed", "user_id", req.UserID)
		}
		return fmt.Errorf("incorrect old password: %w", model.ErrIncorrectPassword)
	}

	// 3. Validate new password strength (optional - can be disabled if not needed)
	requirements := model.DefaultPasswordRequirements()
	err = s.passwordService.ValidatePasswordStrength(req.NewPassword, requirements)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("New password validation failed", "error", err.Error())
		}
		return fmt.Errorf("password validation failed: %w", err)
	}

	// 4. Hash new password
	newHash, err := s.passwordService.HashPassword(req.NewPassword)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to hash new password", "error", err.Error())
		}
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// 5. Update password in database
	if err := s.repo.SetPassword(ctx, req.UserID, newHash); err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to update password", "error", err.Error())
		}
		return fmt.Errorf("failed to update password: %w", err)
	}

	// 6. Invalidate all sessions (logout from all devices).
	// The password is already changed at this point, but session revocation
	// (refresh-token deletion + token_version bump) is part of the operation's
	// security contract: if it fails we must NOT report success, otherwise old
	// access tokens (<=15m) and refresh tokens (<=7d) silently keep working
	// against the new password. Surface the failure so the caller can react
	// (retry revocation / force re-login).
	if err := s.LogoutAll(ctx, req.UserID); err != nil {
		if s.logger != nil {
			s.logger.Error("Password updated but session revocation failed", "user_id", req.UserID, "error", err.Error())
		}
		return fmt.Errorf("password updated but failed to revoke existing sessions: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("Password changed successfully", "user_id", req.UserID)
	}

	return nil
}
