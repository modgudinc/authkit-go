// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"fmt"
	"time"

	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/model"
)

// UserService handles global-identity business logic. A user is a GLOBAL identity
// (no tenant, no roles) keyed by user id or globally-unique email; per-tenant access
// lives on memberships (see MembershipService). Account status (enable/disable,
// lock/unlock) and credentials are identity-level.
type UserService struct {
	sessionsEnabled bool
	repo            *repository.Repository
	logger          logger.Logger
}

// NewUserService creates a new UserService instance
func NewUserService(repo *repository.Repository, logger logger.Logger, opts ...UserOption) *UserService {
	s := &UserService{
		repo:   repo,
		logger: ensureLogger(logger),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

type UserOption func(*UserService)

func WithUserSessions(enabled bool) UserOption {
	return func(s *UserService) { s.sessionsEnabled = enabled }
}

const (
	// defaultListLimit is used when a caller passes a non-positive page size.
	defaultListLimit = 50
	// maxListLimit caps a caller-supplied page size to avoid unbounded scans.
	maxListLimit = 1000
)

// clampPagination bounds caller-supplied paging to a safe range: a non-positive
// limit becomes defaultListLimit, an oversized one is capped at maxListLimit, and
// a negative offset becomes 0 (a negative SQL LIMIT/OFFSET is otherwise an error).
func clampPagination(limit, offset int) (int, int) {
	switch {
	case limit <= 0:
		limit = defaultListLimit
	case limit > maxListLimit:
		limit = maxListLimit
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// ============================================================================
// User Creation & Management
// ============================================================================

// Create creates a new GLOBAL user with the provided details. The email is
// normalized (trimmed and lowercased) so it can be matched consistently on later
// lookups, and must be globally unique. Grant tenant access separately via
// MembershipService.Add.
func (s *UserService) Create(ctx context.Context, req model.CreateUserRequest) (string, error) {
	req.Email = normalizeEmail(req.Email)
	if !isValidEmail(req.Email) {
		return "", fmt.Errorf("create user: invalid email: %w", model.ErrInvalidInput)
	}
	id, err := s.repo.Create(ctx, req)
	return id, sanitizeError(ctx, s.logger, "create user", err)
}

// Update updates a user's display name (identity-level, keyed by req.UserID). Roles
// are no longer here — they are per-tenant; change them via
// MembershipService.UpdateRoles. A display-name change does not invalidate tokens.
func (s *UserService) Update(ctx context.Context, req model.UpdateUserRequest) error {
	return sanitizeError(ctx, s.logger, "update user", s.repo.Update(ctx, req.UserID, req))
}

// Delete soft-deletes a user (sets is_enabled=false) and revokes its refresh tokens.
// Keyed by the global user id.
func (s *UserService) Delete(ctx context.Context, userID string) error {
	if err := s.repo.Delete(ctx, userID); err != nil {
		return sanitizeError(ctx, s.logger, "delete user", err)
	}
	return sanitizeError(ctx, s.logger, "delete user", s.revokeRefreshTokens(ctx, userID, "delete"))
}

// ============================================================================
// Query Methods (keyed by global user id or globally-unique email)
// ============================================================================

// GetByID retrieves a user by global id.
func (s *UserService) GetByID(ctx context.Context, userID string) (*model.User, error) {
	u, err := s.repo.GetByID(ctx, userID)
	return u, sanitizeError(ctx, s.logger, "get user by id", err)
}

// GetByEmail retrieves a user by email (case-insensitive; email is globally unique).
func (s *UserService) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	u, err := s.repo.GetByEmail(ctx, normalizeEmail(email))
	return u, sanitizeError(ctx, s.logger, "get user by email", err)
}

// Exists reports whether a user exists for an email (case-insensitive, global).
func (s *UserService) Exists(ctx context.Context, email string) (bool, error) {
	ok, err := s.repo.Exists(ctx, normalizeEmail(email))
	return ok, sanitizeError(ctx, s.logger, "check user exists", err)
}

// List retrieves users with pagination (a global, cross-tenant admin listing; for a
// tenant's members use MembershipService.ListByTenant). limit/offset are clamped
// (see clampPagination) so caller-supplied values can't request an unbounded scan or
// produce an invalid SQL LIMIT.
func (s *UserService) List(ctx context.Context, limit, offset int) ([]*model.User, error) {
	limit, offset = clampPagination(limit, offset)
	users, err := s.repo.List(ctx, limit, offset)
	return users, sanitizeError(ctx, s.logger, "list users", err)
}

// ============================================================================
// Active User Methods (for actor linking)
// ============================================================================

// ExistsActive reports whether an active (enabled, unlocked) user exists for an
// email. Useful when linking external actors to users.
func (s *UserService) ExistsActive(ctx context.Context, email string) (bool, error) {
	ok, err := s.repo.ExistsActive(ctx, normalizeEmail(email))
	return ok, sanitizeError(ctx, s.logger, "check active user exists", err)
}

// GetDisplayName gets just the display name for a user. Useful when enriching
// responses with user names.
func (s *UserService) GetDisplayName(ctx context.Context, userID string) (string, error) {
	name, err := s.repo.GetDisplayName(ctx, userID)
	return name, sanitizeError(ctx, s.logger, "get display name", err)
}

// GetActiveUserIDByEmail gets the user ID for an active (enabled, unlocked) user by
// email. Useful when linking external actors to users by email.
func (s *UserService) GetActiveUserIDByEmail(ctx context.Context, email string) (string, error) {
	id, err := s.repo.GetActiveUserIDByEmail(ctx, normalizeEmail(email))
	return id, sanitizeError(ctx, s.logger, "get active user id by email", err)
}

// ============================================================================
// Account Status (Security Control)
// ============================================================================

// Lock locks a user account until the specified time and revokes its refresh
// tokens. If lockedUntil is nil, the account is locked indefinitely. Revoking
// refresh tokens prevents a locked account from continuing to mint access tokens
// through the refresh flow.
func (s *UserService) Lock(ctx context.Context, userID string, lockedUntil *time.Time) error {
	if err := s.repo.Lock(ctx, userID, lockedUntil); err != nil {
		return sanitizeError(ctx, s.logger, "lock user", err)
	}
	return sanitizeError(ctx, s.logger, "lock user", s.revokeRefreshTokens(ctx, userID, "lock"))
}

// Unlock unlocks a user account and resets its failed-login count.
func (s *UserService) Unlock(ctx context.Context, userID string) error {
	return sanitizeError(ctx, s.logger, "unlock user", s.repo.Unlock(ctx, userID))
}

// ============================================================================
// Password Management
// ============================================================================

// SetPassword sets the (already-hashed) password for a user and revokes the user's
// refresh tokens (a password change should end existing sessions).
func (s *UserService) SetPassword(ctx context.Context, userID, hashedPassword string) error {
	if err := s.repo.SetPassword(ctx, userID, hashedPassword); err != nil {
		return sanitizeError(ctx, s.logger, "set password", err)
	}
	return sanitizeError(ctx, s.logger, "set password", s.revokeRefreshTokens(ctx, userID, "set_password"))
}

// VerifyPassword retrieves the stored password hash for verification. Returns the
// hash which should be compared using bcrypt.
func (s *UserService) VerifyPassword(ctx context.Context, userID string) (string, error) {
	hash, err := s.repo.VerifyPassword(ctx, userID)
	return hash, sanitizeError(ctx, s.logger, "verify password", err)
}

// ============================================================================
// Email Verification
// ============================================================================

// MarkEmailVerified records that the user proved they own their current email
// address, for example by entering a code from OTPService that was sent to it. Call
// it only after such a proof: ExternalIdentityService.Resolve trusts the record when
// it links a provider sign-in to this user. Accepting an invitation is not a proof,
// because whoever created the invitation knows its code. The first verification
// time is kept. Returns ErrNotFound for an unknown user.
func (s *UserService) MarkEmailVerified(ctx context.Context, userID string) error {
	if userID == "" {
		return fmt.Errorf("user id is required: %w", model.ErrInvalidInput)
	}
	if err := s.repo.MarkEmailVerified(ctx, userID); err != nil {
		return sanitizeError(ctx, s.logger, "mark email verified", err)
	}
	s.logger.Info(ctx, "Email marked verified", "user_id", userID)
	return nil
}

// ============================================================================
// Activity Tracking
// ============================================================================

// UpdateLastLogin updates the last_login timestamp for a user.
func (s *UserService) UpdateLastLogin(ctx context.Context, userID string) error {
	return sanitizeError(ctx, s.logger, "update last login", s.repo.UpdateLastLogin(ctx, userID))
}

// IncrementFailedLoginCount increments the failed login counter for a user.
func (s *UserService) IncrementFailedLoginCount(ctx context.Context, userID string) error {
	return sanitizeError(ctx, s.logger, "increment failed login count", s.repo.IncrementFailedLoginCount(ctx, userID))
}

// ============================================================================
// Token Management
// ============================================================================

// IncrementTokenVersion increments the identity token_version and revokes the user's
// refresh tokens, invalidating all existing access AND refresh tokens for every
// workspace.
//
// The token_version bump invalidates outstanding JWTs (checked in ValidateJWT), but
// refresh tokens are not version-stamped, so they must be deleted explicitly.
// Otherwise a version bump alone could be defeated by refreshing: rotation reads the
// new version and stamps it into a freshly minted, valid access token.
func (s *UserService) IncrementTokenVersion(ctx context.Context, userID string) error {
	if err := s.repo.IncrementTokenVersion(ctx, userID); err != nil {
		return sanitizeError(ctx, s.logger, "increment token version", err)
	}
	return sanitizeError(ctx, s.logger, "increment token version", s.revokeRefreshTokens(ctx, userID, "increment_token_version"))
}

// revokeRefreshTokens deletes all refresh tokens for a user. Used by the
// account-status mutators that must terminate existing sessions.
func (s *UserService) revokeRefreshTokens(ctx context.Context, userID string, reason string) error {
	if s.sessionsEnabled {
		return s.repo.RevokeUserSessionsAndTokens(ctx, userID)
	}
	if err := s.repo.DeleteByUserID(ctx, userID); err != nil {
		s.logger.Error(ctx, "Failed to revoke refresh tokens",
			"user_id", userID,
			"reason", reason,
			"error", err.Error(),
		)
		return err
	}
	return nil
}

// ============================================================================
// Account Status & Audit (admin)
// ============================================================================

// StatusHistory returns a user's account status-change audit trail (enable/disable/
// lock/unlock, including automatic failed-login lockouts), newest first, keyed by the
// global user id.
func (s *UserService) StatusHistory(ctx context.Context, userID string) ([]*model.UserStatusChange, error) {
	changes, err := s.repo.ListUserStatusChanges(ctx, userID)
	return changes, sanitizeError(ctx, s.logger, "list status history", err)
}

// CleanupStatusChanges deletes status-change audit rows older than olderThan and
// returns the number removed. The audit table has no expiry, so run this
// periodically (e.g. a daily job) per your retention policy to bound its growth.
// olderThan must be positive — a non-positive value is rejected rather than
// silently deleting the entire audit trail.
func (s *UserService) CleanupStatusChanges(ctx context.Context, olderThan time.Duration) (int64, error) {
	if olderThan <= 0 {
		return 0, fmt.Errorf("status-change retention period must be positive (got %s)", olderThan)
	}
	n, err := s.repo.CleanupStatusChanges(ctx, time.Now().Add(-olderThan))
	return n, sanitizeError(ctx, s.logger, "cleanup status changes", err)
}

// Enable enables a disabled user account.
func (s *UserService) Enable(ctx context.Context, userID string) error {
	return sanitizeError(ctx, s.logger, "enable user", s.repo.Enable(ctx, userID))
}

// Disable disables a user account and revokes its refresh tokens.
//
// repo.Disable also bumps token_version (invalidating outstanding access tokens).
// Refresh tokens are opaque and not tied to token_version, so they are deleted
// explicitly here — otherwise a disabled-then-re-enabled account could resume old
// sessions from refresh tokens that were never replayed.
func (s *UserService) Disable(ctx context.Context, userID string) error {
	if err := s.repo.Disable(ctx, userID); err != nil {
		return sanitizeError(ctx, s.logger, "disable user", err)
	}
	return sanitizeError(ctx, s.logger, "disable user", s.revokeRefreshTokens(ctx, userID, "disable"))
}
