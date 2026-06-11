// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/model"
	"github.com/modgudinc/authkit-go/repository"
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
		logger: logger,
	}
}

// ============================================================================
// User Creation & Management
// ============================================================================

// Create creates a new user with the provided details. The email is normalized
// (trimmed and lowercased) so it can be matched consistently on later lookups.
func (s *UserService) Create(ctx context.Context, req model.CreateUserRequest) (uuid.UUID, error) {
	req.Email = normalizeEmail(req.Email)
	return s.repo.Create(ctx, req)
}

// Update updates a user's roles and display name within a tenant.
//
// The tenantID is required and the update is scoped to it, so an admin in one
// tenant cannot modify a user in another tenant by supplying its id (IDOR).
func (s *UserService) Update(ctx context.Context, userID uuid.UUID, tenantID string, req model.UpdateUserRequest) error {
	return s.repo.UpdateByTenant(ctx, userID, tenantID, req)
}

// Delete soft-deletes a user (sets is_enabled=false) within a tenant and revokes
// its refresh tokens. Scoped by tenantID to prevent cross-tenant deletion.
func (s *UserService) Delete(ctx context.Context, userID uuid.UUID, tenantID string) error {
	if err := s.repo.DeleteByTenant(ctx, userID, tenantID); err != nil {
		return err
	}
	return s.revokeRefreshTokens(ctx, userID, "delete")
}

// ============================================================================
// Query Methods (all scoped by tenant_id)
// ============================================================================

// GetByID retrieves a user by ID within a specific tenant
func (s *UserService) GetByID(ctx context.Context, userID uuid.UUID, tenantID string) (*model.User, error) {
	return s.repo.GetByID(ctx, userID, tenantID)
}

// GetByIDOnly retrieves a user by ID without tenant scoping
// Used for internal operations where tenant is not yet known
func (s *UserService) GetByIDOnly(ctx context.Context, userID uuid.UUID) (*model.User, error) {
	return s.repo.GetByIDOnly(ctx, userID)
}

// GetByEmail retrieves a user by email within a specific tenant
func (s *UserService) GetByEmail(ctx context.Context, email, tenantID string) (*model.User, error) {
	return s.repo.GetByEmail(ctx, normalizeEmail(email), tenantID)
}

// Exists checks if a user exists within a specific tenant
func (s *UserService) Exists(ctx context.Context, email, tenantID string) (bool, error) {
	return s.repo.Exists(ctx, normalizeEmail(email), tenantID)
}

// List retrieves users within a specific tenant with pagination
func (s *UserService) List(ctx context.Context, tenantID string, limit, offset int) ([]*model.User, error) {
	return s.repo.List(ctx, tenantID, limit, offset)
}

// ============================================================================
// Active User Methods (for actor linking)
// ============================================================================

// ExistsActive checks if an active (enabled, unlocked) user exists
// Useful when linking external actors to users
func (s *UserService) ExistsActive(ctx context.Context, email, tenantID string) (bool, error) {
	return s.repo.ExistsActive(ctx, normalizeEmail(email), tenantID)
}

// GetDisplayName gets just the display name for a user
// Useful when enriching responses with user names
func (s *UserService) GetDisplayName(ctx context.Context, userID uuid.UUID) (string, error) {
	return s.repo.GetDisplayName(ctx, userID)
}

// GetActiveUserIDByEmail gets user ID for an active (enabled, unlocked) user
// Useful when linking external actors to users by email
func (s *UserService) GetActiveUserIDByEmail(ctx context.Context, email, tenantID string) (uuid.UUID, error) {
	return s.repo.GetActiveUserIDByEmail(ctx, normalizeEmail(email), tenantID)
}

// ============================================================================
// Account Status (Admin Control)
// ============================================================================

// Enable enables a user account within a tenant (scoped to prevent IDOR).
func (s *UserService) Enable(ctx context.Context, userID uuid.UUID, tenantID string) error {
	return s.repo.EnableByTenant(ctx, userID, tenantID)
}

// Disable disables a user account within a tenant and revokes its refresh tokens.
//
// Scoped by tenantID so one tenant cannot disable another tenant's user.
// Refresh tokens are opaque random values not tied to token_version, so a status
// change alone does not invalidate them; without revoking them here a disabled
// account could keep minting new access tokens via the refresh flow.
func (s *UserService) Disable(ctx context.Context, userID uuid.UUID, tenantID string) error {
	if err := s.repo.DisableByTenant(ctx, userID, tenantID); err != nil {
		return err
	}
	return s.revokeRefreshTokens(ctx, userID, "disable")
}

// ============================================================================
// Account Status (Security Control)
// ============================================================================

// Lock locks a user account within a tenant until the specified time and revokes
// its refresh tokens. If lockedUntil is nil, the account is locked indefinitely.
//
// Scoped by tenantID. Revoking refresh tokens prevents a locked account from
// continuing to mint access tokens through the refresh flow while locked.
func (s *UserService) Lock(ctx context.Context, userID uuid.UUID, tenantID string, lockedUntil *time.Time) error {
	if err := s.repo.LockByTenant(ctx, userID, tenantID, lockedUntil); err != nil {
		return err
	}
	return s.revokeRefreshTokens(ctx, userID, "lock")
}

// Unlock unlocks a user account within a tenant (scoped to prevent IDOR).
func (s *UserService) Unlock(ctx context.Context, userID uuid.UUID, tenantID string) error {
	return s.repo.UnlockByTenant(ctx, userID, tenantID)
}

// ============================================================================
// Password Management
// ============================================================================

// SetPassword sets the password hash for a user within a tenant and revokes the
// user's refresh tokens (a password change should end existing sessions).
// The password must already be hashed. Scoped by tenantID to prevent IDOR.
func (s *UserService) SetPassword(ctx context.Context, userID uuid.UUID, tenantID, hashedPassword string) error {
	if err := s.repo.SetPasswordByTenant(ctx, userID, tenantID, hashedPassword); err != nil {
		return err
	}
	return s.revokeRefreshTokens(ctx, userID, "set_password")
}

// VerifyPassword retrieves the password hash for verification
// Returns the stored hash which should be compared using bcrypt
func (s *UserService) VerifyPassword(ctx context.Context, userID uuid.UUID) (string, error) {
	return s.repo.VerifyPassword(ctx, userID)
}

// ============================================================================
// Activity Tracking
// ============================================================================

// UpdateLastLogin updates the last_login timestamp for a user
func (s *UserService) UpdateLastLogin(ctx context.Context, userID uuid.UUID) error {
	return s.repo.UpdateLastLogin(ctx, userID)
}

// IncrementFailedLoginCount increments the failed login counter
func (s *UserService) IncrementFailedLoginCount(ctx context.Context, userID uuid.UUID) error {
	return s.repo.IncrementFailedLoginCount(ctx, userID)
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
func (s *UserService) IncrementTokenVersion(ctx context.Context, userID uuid.UUID, tenantID string) error {
	if err := s.repo.IncrementTokenVersionByTenant(ctx, userID, tenantID); err != nil {
		return err
	}
	return s.revokeRefreshTokens(ctx, userID, "increment_token_version")
}

// revokeRefreshTokens deletes all refresh tokens for a user. Used by the
// account-status mutators that must terminate existing sessions.
func (s *UserService) revokeRefreshTokens(ctx context.Context, userID uuid.UUID, reason string) error {
	if err := s.repo.DeleteByUserID(ctx, userID); err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to revoke refresh tokens",
				"user_id", userID.String(),
				"reason", reason,
				"error", err.Error(),
			)
		}
		return err
	}
	return nil
}

// ============================================================================
// Tenant-Scoped Operations (for admin user management APIs)
// ============================================================================

// CountByTenant returns the count of users in a tenant
func (s *UserService) CountByTenant(ctx context.Context, tenantID string) (int, error) {
	return s.repo.CountUsersByTenant(ctx, tenantID)
}

// UpdateRolesByTenant updates user roles with tenant isolation
// Used by admin APIs to ensure tenant ownership before modification
func (s *UserService) UpdateRolesByTenant(ctx context.Context, userID uuid.UUID, tenantID string, roles []string) error {
	return s.repo.UpdateRolesByTenant(ctx, userID, tenantID, roles)
}

// EnableByTenant enables a user account with tenant isolation
// Validates tenant ownership before enabling
func (s *UserService) EnableByTenant(ctx context.Context, userID uuid.UUID, tenantID string) error {
	return s.repo.EnableByTenant(ctx, userID, tenantID)
}

// DisableByTenant disables a user account with tenant isolation
// Validates tenant ownership and increments token_version to invalidate all JWTs
func (s *UserService) DisableByTenant(ctx context.Context, userID uuid.UUID, tenantID string) error {
	return s.repo.DisableByTenant(ctx, userID, tenantID)
}
