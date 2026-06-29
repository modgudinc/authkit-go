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

// UserService handles user-related business logic
type UserService struct {
	repo   *repository.Repository
	logger logger.Logger
}

// NewUserService creates a new UserService instance
func NewUserService(repo *repository.Repository, logger logger.Logger) *UserService {
	return &UserService{
		repo:   repo,
		logger: ensureLogger(logger),
	}
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

// Create creates a new user with the provided details. The email is normalized
// (trimmed and lowercased) so it can be matched consistently on later lookups.
func (s *UserService) Create(ctx context.Context, req model.CreateUserRequest) (string, error) {
	req.Email = normalizeEmail(req.Email)
	id, err := s.repo.Create(ctx, req)
	return id, sanitizeError(ctx, s.logger, "create user", err)
}

// Update updates a user's roles and/or display name. req.UserID + req.TenantID
// identify the target; the update is tenant-scoped, so an admin in one tenant
// cannot modify a user in another by supplying its id (IDOR). It bumps the user's
// token_version, so any outstanding access tokens (which carry roles) are
// invalidated and the client must refresh to obtain tokens with the updated roles.
// The refresh token itself remains valid (the user is not logged out), so the next
// refresh seamlessly issues correctly-scoped tokens.
func (s *UserService) Update(ctx context.Context, req model.UpdateUserRequest) error {
	return sanitizeError(ctx, s.logger, "update user", s.repo.UpdateByTenant(ctx, req.UserID, req.TenantID, req))
}

// Delete soft-deletes a user (sets is_enabled=false) within a tenant and revokes
// its refresh tokens. Scoped by tenantID to prevent cross-tenant deletion.
func (s *UserService) Delete(ctx context.Context, userID string, tenantID string) error {
	if err := s.repo.DeleteByTenant(ctx, userID, tenantID); err != nil {
		return sanitizeError(ctx, s.logger, "delete user", err)
	}
	return sanitizeError(ctx, s.logger, "delete user", s.revokeRefreshTokens(ctx, userID, "delete"))
}

// ============================================================================
// Query Methods (all scoped by tenant_id)
// ============================================================================

// GetByID retrieves a user by ID within a specific tenant
func (s *UserService) GetByID(ctx context.Context, userID string, tenantID string) (*model.User, error) {
	u, err := s.repo.GetByID(ctx, userID, tenantID)
	return u, sanitizeError(ctx, s.logger, "get user by id", err)
}

// GetByEmail retrieves a user by email within a specific tenant
func (s *UserService) GetByEmail(ctx context.Context, email, tenantID string) (*model.User, error) {
	u, err := s.repo.GetByEmail(ctx, normalizeEmail(email), tenantID)
	return u, sanitizeError(ctx, s.logger, "get user by email", err)
}

// Exists checks if a user exists within a specific tenant
func (s *UserService) Exists(ctx context.Context, email, tenantID string) (bool, error) {
	ok, err := s.repo.Exists(ctx, normalizeEmail(email), tenantID)
	return ok, sanitizeError(ctx, s.logger, "check user exists", err)
}

// List retrieves users within a specific tenant with pagination. limit/offset are
// clamped (see clampPagination) so caller-supplied values can't request an
// unbounded scan or produce an invalid SQL LIMIT.
func (s *UserService) List(ctx context.Context, tenantID string, limit, offset int) ([]*model.User, error) {
	limit, offset = clampPagination(limit, offset)
	users, err := s.repo.List(ctx, tenantID, limit, offset)
	return users, sanitizeError(ctx, s.logger, "list users", err)
}

// ============================================================================
// Active User Methods (for actor linking)
// ============================================================================

// ExistsActive checks if an active (enabled, unlocked) user exists
// Useful when linking external actors to users
func (s *UserService) ExistsActive(ctx context.Context, email, tenantID string) (bool, error) {
	ok, err := s.repo.ExistsActive(ctx, normalizeEmail(email), tenantID)
	return ok, sanitizeError(ctx, s.logger, "check active user exists", err)
}

// GetDisplayName gets just the display name for a user within a tenant (scoped to
// prevent reading a user that belongs to another tenant).
// Useful when enriching responses with user names.
func (s *UserService) GetDisplayName(ctx context.Context, userID string, tenantID string) (string, error) {
	name, err := s.repo.GetDisplayNameByTenant(ctx, userID, tenantID)
	return name, sanitizeError(ctx, s.logger, "get display name", err)
}

// GetActiveUserIDByEmail gets user ID for an active (enabled, unlocked) user
// Useful when linking external actors to users by email
func (s *UserService) GetActiveUserIDByEmail(ctx context.Context, email, tenantID string) (string, error) {
	id, err := s.repo.GetActiveUserIDByEmail(ctx, normalizeEmail(email), tenantID)
	return id, sanitizeError(ctx, s.logger, "get active user id by email", err)
}

// ============================================================================
// Account Status (Security Control)
// ============================================================================

// Lock locks a user account within a tenant until the specified time and revokes
// its refresh tokens. If lockedUntil is nil, the account is locked indefinitely.
//
// Scoped by tenantID. Revoking refresh tokens prevents a locked account from
// continuing to mint access tokens through the refresh flow while locked.
func (s *UserService) Lock(ctx context.Context, userID string, tenantID string, lockedUntil *time.Time) error {
	if err := s.repo.LockByTenant(ctx, userID, tenantID, lockedUntil); err != nil {
		return sanitizeError(ctx, s.logger, "lock user", err)
	}
	return sanitizeError(ctx, s.logger, "lock user", s.revokeRefreshTokens(ctx, userID, "lock"))
}

// Unlock unlocks a user account within a tenant (scoped to prevent IDOR).
func (s *UserService) Unlock(ctx context.Context, userID string, tenantID string) error {
	return sanitizeError(ctx, s.logger, "unlock user", s.repo.UnlockByTenant(ctx, userID, tenantID))
}

// ============================================================================
// Password Management
// ============================================================================

// SetPassword sets the password hash for a user within a tenant and revokes the
// user's refresh tokens (a password change should end existing sessions).
// The password must already be hashed. Scoped by tenantID to prevent IDOR.
func (s *UserService) SetPassword(ctx context.Context, userID string, tenantID, hashedPassword string) error {
	if err := s.repo.SetPasswordByTenant(ctx, userID, tenantID, hashedPassword); err != nil {
		return sanitizeError(ctx, s.logger, "set password", err)
	}
	return sanitizeError(ctx, s.logger, "set password", s.revokeRefreshTokens(ctx, userID, "set_password"))
}

// VerifyPassword retrieves the password hash for verification within a tenant
// (scoped so a caller-supplied user id from another tenant cannot read its hash).
// Returns the stored hash which should be compared using bcrypt.
func (s *UserService) VerifyPassword(ctx context.Context, userID string, tenantID string) (string, error) {
	hash, err := s.repo.VerifyPasswordByTenant(ctx, userID, tenantID)
	return hash, sanitizeError(ctx, s.logger, "verify password", err)
}

// ============================================================================
// Activity Tracking
// ============================================================================

// UpdateLastLogin updates the last_login timestamp for a user within a tenant
// (scoped so a caller-supplied user id from another tenant cannot be touched).
func (s *UserService) UpdateLastLogin(ctx context.Context, userID string, tenantID string) error {
	return sanitizeError(ctx, s.logger, "update last login", s.repo.UpdateLastLoginByTenant(ctx, userID, tenantID))
}

// IncrementFailedLoginCount increments the failed login counter for a user within
// a tenant (scoped so a caller-supplied user id from another tenant cannot be
// driven toward lockout).
func (s *UserService) IncrementFailedLoginCount(ctx context.Context, userID string, tenantID string) error {
	return sanitizeError(ctx, s.logger, "increment failed login count", s.repo.IncrementFailedLoginCountByTenant(ctx, userID, tenantID))
}

// ============================================================================
// Token Management
// ============================================================================

// IncrementTokenVersion increments the token version and revokes the user's
// refresh tokens, invalidating all existing access AND refresh tokens.
//
// The token_version bump invalidates outstanding JWTs (checked in ValidateJWT),
// but refresh tokens are not version-stamped, so they must be deleted explicitly.
// Otherwise a version bump alone could be defeated by refreshing: rotation reads
// the new version and stamps it into a freshly minted, valid access token.
func (s *UserService) IncrementTokenVersion(ctx context.Context, userID string, tenantID string) error {
	if err := s.repo.IncrementTokenVersionByTenant(ctx, userID, tenantID); err != nil {
		return sanitizeError(ctx, s.logger, "increment token version", err)
	}
	return sanitizeError(ctx, s.logger, "increment token version", s.revokeRefreshTokens(ctx, userID, "increment_token_version"))
}

// revokeRefreshTokens deletes all refresh tokens for a user. Used by the
// account-status mutators that must terminate existing sessions.
func (s *UserService) revokeRefreshTokens(ctx context.Context, userID string, reason string) error {
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
// Account Status, Roles & Counts (admin, tenant-scoped)
// ============================================================================

// Count returns the number of users in a tenant.
func (s *UserService) Count(ctx context.Context, tenantID string) (int, error) {
	n, err := s.repo.CountUsersByTenant(ctx, tenantID)
	return n, sanitizeError(ctx, s.logger, "count users", err)
}

// StatusHistory returns a user's account status-change audit trail (enable/disable/
// lock/unlock, including automatic failed-login lockouts), newest first. It is
// tenant-scoped: a cross-tenant userID yields an empty result, not another tenant's
// audit rows.
func (s *UserService) StatusHistory(ctx context.Context, userID string, tenantID string) ([]*model.UserStatusChange, error) {
	changes, err := s.repo.ListUserStatusChanges(ctx, userID, tenantID)
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

// UpdateRoles replaces a user's roles, scoped to the tenant (an admin in one tenant
// cannot modify a user in another). It bumps the user's token_version so outstanding
// access tokens (which carry roles) are invalidated; the next refresh issues tokens
// with the updated roles.
func (s *UserService) UpdateRoles(ctx context.Context, userID string, tenantID string, roles []string) error {
	return sanitizeError(ctx, s.logger, "update roles", s.repo.UpdateRolesByTenant(ctx, userID, tenantID, roles))
}

// Enable enables a user account, scoped to the tenant (validates tenant ownership).
func (s *UserService) Enable(ctx context.Context, userID string, tenantID string) error {
	return sanitizeError(ctx, s.logger, "enable user", s.repo.EnableByTenant(ctx, userID, tenantID))
}

// Disable disables a user account, scoped to the tenant, and revokes its refresh
// tokens.
//
// repo.DisableByTenant also bumps token_version (invalidating outstanding access
// tokens). Refresh tokens are opaque and not tied to token_version, so they are
// deleted explicitly here — otherwise a disabled-then-re-enabled account could
// resume old sessions from refresh tokens that were never replayed.
func (s *UserService) Disable(ctx context.Context, userID string, tenantID string) error {
	if err := s.repo.DisableByTenant(ctx, userID, tenantID); err != nil {
		return sanitizeError(ctx, s.logger, "disable user", err)
	}
	return sanitizeError(ctx, s.logger, "disable user", s.revokeRefreshTokens(ctx, userID, "disable"))
}
