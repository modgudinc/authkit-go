// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	uuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/modgudinc/authkit-go/model"
)

// Identity Repository Methods:
//
// User Management:
// - Create        - Creates a new user with default status (enabled, unlocked)
// - Update        - Updates user's roles and display_name only
// - Delete        - Soft deletes a user (sets is_enabled=false)
//
// Password Management:
// - SetPassword   - Sets the password hash (accepts hashed password only)
// - VerifyPassword - Retrieves password hash for verification
//
// Query Methods (all scoped by tenant_id):
// - GetByID       - Retrieves a user by ID within a specific tenant
// - GetByEmail    - Retrieves a user by email within a specific tenant
// - Exists        - Checks if a user exists within a specific tenant
// - List          - Lists users within a specific tenant with pagination
//
// Account Status (Admin Control):
// - Enable        - Enables a disabled user account
// - Disable       - Disables a user account (reversible admin action)
//
// Account Status (Security Control):
// - Lock          - Locks a user account with optional auto-unlock
// - Unlock        - Unlocks a user account and resets failed login count
//
// Activity Tracking:
// - UpdateLastLogin - Updates the last login timestamp after successful authentication
//
// Token Management:
// - IncrementTokenVersion - Invalidates all existing JWTs for the user

// ============================================================================
// Create - Creates a new user with default status (enabled, unlocked)
// ============================================================================
func (r *Repository) Create(ctx context.Context, user model.CreateUserRequest) (uuid.UUID, error) {
	userID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("could not generate an id for user: %w", err)
	}

	now := time.Now()

	rolesJSON, err := json.Marshal(user.Roles)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to marshal roles: %w", err)
	}

	query := `
		INSERT INTO {{schema}}.users (
			id, email, password_hash, tenant_id, display_name, roles, token_version,
			is_enabled, is_locked, failed_login_count,
			created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err = r.rw.ExecContext(ctx, r.q(query),
		userID,
		user.Email,
		user.PasswordHash,
		user.TenantID,
		user.DisplayName,
		rolesJSON,
		0,     // token_version (default)
		true,  // is_enabled (default: enabled)
		false, // is_locked (default: not locked)
		0,     // failed_login_count (default: 0)
		now,   // created_at
		now,   // updated_at
	)
	if err != nil {
		// A (tenant_id, email) uniqueness conflict means an account already
		// exists for this email; surface a clean sentinel instead of the raw
		// driver/constraint string so callers can errors.Is it.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return uuid.Nil, fmt.Errorf("user already exists for this tenant: %w", model.ErrUserExists)
		}
		return uuid.Nil, fmt.Errorf("failed to create user: %w", err)
	}

	return userID, nil
}

// ============================================================================
// Update - Updates user's roles and display_name only
// Security-critical fields (email, password, status) must use dedicated methods
// ============================================================================
func (r *Repository) Update(ctx context.Context, userID uuid.UUID, req model.UpdateUserRequest) error {
	rolesJSON, err := json.Marshal(req.Roles)
	if err != nil {
		return fmt.Errorf("failed to marshal roles: %w", err)
	}

	query := `
		UPDATE {{schema}}.users
		SET
			display_name = $1,
			roles = $2,
			updated_at = $3
		WHERE id = $4
	`

	result, err := r.rw.ExecContext(ctx, r.q(query),
		req.DisplayName,
		rolesJSON,
		time.Now(),
		userID,
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}

	return nil
}

// ============================================================================
// SetPassword - Sets the password hash for a user (low-level operation)
// IMPORTANT: This method accepts a HASHED password, not plaintext
// Password hashing must be done at the service/controller layer
// ============================================================================
func (r *Repository) SetPassword(ctx context.Context, userID uuid.UUID, hashedPassword string) error {
	query := `
		UPDATE {{schema}}.users
		SET
			password_hash = $1,
			updated_at = $2
		WHERE id = $3
	`

	result, err := r.rw.ExecContext(ctx, r.q(query),
		hashedPassword,
		time.Now(),
		userID,
	)
	if err != nil {
		return fmt.Errorf("failed to set password: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}

	return nil
}

// ============================================================================
// VerifyPassword - Retrieves the stored password hash for verification
// IMPORTANT: Returns the HASHED password for comparison at service layer
// Password verification (hash comparison) must be done at service/controller layer
// ============================================================================
func (r *Repository) VerifyPassword(ctx context.Context, userID uuid.UUID) (string, error) {
	query := `
		SELECT password_hash
		FROM {{schema}}.users
		WHERE id = $1
	`

	var hashedPassword string
	err := r.ro.QueryRowContext(ctx, r.q(query), userID).Scan(&hashedPassword)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("user not found: %w", model.ErrNotFound)
		}
		return "", fmt.Errorf("failed to get password hash: %w", err)
	}

	return hashedPassword, nil
}

// ============================================================================
// Delete - Soft deletes a user by setting is_enabled=false and disabled_at
// This preserves user data for audit trails while preventing authentication
// ============================================================================
func (r *Repository) Delete(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE {{schema}}.users
		SET
			is_enabled = false,
			disabled_at = $1,
			updated_at = $1
		WHERE id = $2
	`

	now := time.Now()
	result, err := r.rw.ExecContext(ctx, r.q(query), now, userID)
	if err != nil {
		return fmt.Errorf("failed to soft delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}

	return nil
}

// ============================================================================
// GetByID - Retrieves a user by ID within a specific tenant
// Scoped by tenant_id to prevent cross-tenant access
// ============================================================================
func (r *Repository) GetByID(ctx context.Context, userID uuid.UUID, tenantID string) (*model.User, error) {
	query := `
		SELECT
			id, email, password_hash, tenant_id, display_name, roles, token_version,
			is_enabled, disabled_at, is_locked, locked_until, failed_login_count, last_failed_login, last_login,
			created_at, updated_at
		FROM {{schema}}.users
		WHERE id = $1 AND tenant_id = $2
	`

	var user model.User
	var rolesJSON []byte
	var disabledAt, lockedUntil, lastFailedLogin, lastLogin *time.Time

	err := r.ro.QueryRowContext(ctx, r.q(query), userID, tenantID).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.TenantID,
		&user.DisplayName,
		&rolesJSON,
		&user.TokenVersion,
		&user.IsEnabled,
		&disabledAt,
		&user.IsLocked,
		&lockedUntil,
		&user.FailedLoginCount,
		&lastFailedLogin,
		&lastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user not found: %w", model.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}

	// Unmarshal roles from JSONB
	if err := json.Unmarshal(rolesJSON, &user.Roles); err != nil {
		return nil, fmt.Errorf("failed to unmarshal roles: %w", err)
	}

	// Set nullable fields
	user.DisabledAt = disabledAt
	user.LockedUntil = lockedUntil
	user.LastFailedLoginAt = lastFailedLogin
	user.LastLoginAt = lastLogin

	return &user, nil
}

// ============================================================================
// GetByIDOnly - Retrieves a user by ID without tenant_id constraint
// Used for refresh token validation where user_id is sufficient (UUID is unique)
// ============================================================================
func (r *Repository) GetByIDOnly(ctx context.Context, userID uuid.UUID) (*model.User, error) {
	query := `
		SELECT
			id, email, password_hash, tenant_id, display_name, roles, token_version,
			is_enabled, disabled_at, is_locked, locked_until, failed_login_count, last_failed_login, last_login,
			created_at, updated_at
		FROM {{schema}}.users
		WHERE id = $1
	`

	var user model.User
	var rolesJSON []byte
	var disabledAt, lockedUntil, lastFailedLogin, lastLogin *time.Time

	err := r.ro.QueryRowContext(ctx, r.q(query), userID).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.TenantID,
		&user.DisplayName,
		&rolesJSON,
		&user.TokenVersion,
		&user.IsEnabled,
		&disabledAt,
		&user.IsLocked,
		&lockedUntil,
		&user.FailedLoginCount,
		&lastFailedLogin,
		&lastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user not found: %w", model.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}

	// Unmarshal roles from JSONB
	if err := json.Unmarshal(rolesJSON, &user.Roles); err != nil {
		return nil, fmt.Errorf("failed to unmarshal roles: %w", err)
	}

	// Set nullable fields
	user.DisabledAt = disabledAt
	user.LockedUntil = lockedUntil
	user.LastFailedLoginAt = lastFailedLogin
	user.LastLoginAt = lastLogin

	return &user, nil
}

// ============================================================================
// GetByEmail - Retrieves a user by email within a specific tenant
// Scoped by tenant_id to prevent cross-tenant access
// ============================================================================
func (r *Repository) GetByEmail(ctx context.Context, email string, tenantID string) (*model.User, error) {
	query := `
		SELECT
			id, email, password_hash, tenant_id, display_name, roles, token_version,
			is_enabled, disabled_at, is_locked, locked_until, failed_login_count, last_failed_login, last_login,
			created_at, updated_at
		FROM {{schema}}.users
		WHERE email = $1 AND tenant_id = $2
	`

	var user model.User
	var rolesJSON []byte
	var disabledAt, lockedUntil, lastFailedLogin, lastLogin *time.Time

	err := r.ro.QueryRowContext(ctx, r.q(query), email, tenantID).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.TenantID,
		&user.DisplayName,
		&rolesJSON,
		&user.TokenVersion,
		&user.IsEnabled,
		&disabledAt,
		&user.IsLocked,
		&lockedUntil,
		&user.FailedLoginCount,
		&lastFailedLogin,
		&lastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user not found: %w", model.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	// Unmarshal roles from JSONB
	if err := json.Unmarshal(rolesJSON, &user.Roles); err != nil {
		return nil, fmt.Errorf("failed to unmarshal roles: %w", err)
	}

	// Set nullable fields
	user.DisabledAt = disabledAt
	user.LockedUntil = lockedUntil
	user.LastFailedLoginAt = lastFailedLogin
	user.LastLoginAt = lastLogin

	return &user, nil
}

// ============================================================================
// Exists - Checks if a user exists within a specific tenant
// Scoped by tenant_id for multi-tenant isolation
// ============================================================================
func (r *Repository) Exists(ctx context.Context, email string, tenantID string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1
			FROM {{schema}}.users
			WHERE email = $1 AND tenant_id = $2
		)
	`

	var exists bool
	err := r.ro.QueryRowContext(ctx, r.q(query), email, tenantID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if user exists: %w", err)
	}

	return exists, nil
}

// ============================================================================
// List - Lists users within a specific tenant with pagination
// Scoped by tenant_id for multi-tenant isolation
// Returns users ordered by created_at DESC (newest first)
// ============================================================================
func (r *Repository) List(ctx context.Context, tenantID string, limit, offset int) ([]*model.User, error) {
	query := `
		SELECT
			id, email, password_hash, tenant_id, display_name, roles, token_version,
			is_enabled, disabled_at, is_locked, locked_until, failed_login_count, last_failed_login, last_login,
			created_at, updated_at
		FROM {{schema}}.users
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.ro.QueryContext(ctx, r.q(query), tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var users []*model.User
	for rows.Next() {
		var user model.User
		var rolesJSON []byte
		var disabledAt, lockedUntil, lastFailedLogin, lastLogin *time.Time

		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.PasswordHash,
			&user.TenantID,
			&user.DisplayName,
			&rolesJSON,
			&user.TokenVersion,
			&user.IsEnabled,
			&disabledAt,
			&user.IsLocked,
			&lockedUntil,
			&user.FailedLoginCount,
			&lastFailedLogin,
			&lastLogin,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user row: %w", err)
		}

		// Unmarshal roles from JSONB
		if err := json.Unmarshal(rolesJSON, &user.Roles); err != nil {
			return nil, fmt.Errorf("failed to unmarshal roles: %w", err)
		}

		// Set nullable fields
		user.DisabledAt = disabledAt
		user.LockedUntil = lockedUntil
		user.LastFailedLoginAt = lastFailedLogin
		user.LastLoginAt = lastLogin

		users = append(users, &user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user rows: %w", err)
	}

	return users, nil
}

// ============================================================================
// IncrementTokenVersion - Increments the user's token version
// This invalidates all existing JWTs for the user, forcing re-authentication
// Used for: logout all sessions, password reset, security breach response
// ============================================================================
func (r *Repository) IncrementTokenVersion(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE {{schema}}.users
		SET
			token_version = token_version + 1,
			updated_at = $1
		WHERE id = $2
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to increment token version: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}

	return nil
}

// ============================================================================
// Enable - Enables a disabled user account (admin control)
// Clears the disabled_at timestamp and sets is_enabled to true
// ============================================================================
func (r *Repository) Enable(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE {{schema}}.users
		SET
			is_enabled = true,
			disabled_at = NULL,
			updated_at = $1
		WHERE id = $2
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to enable user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}

	return nil
}

// ============================================================================
// Disable - Disables a user account (admin control)
// Sets is_enabled to false and records the disabled_at timestamp
// Unlike soft delete, this is a reversible admin action
// ============================================================================
func (r *Repository) Disable(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE {{schema}}.users
		SET
			is_enabled = false,
			disabled_at = $1,
			updated_at = $1
		WHERE id = $2
	`

	now := time.Now()
	result, err := r.rw.ExecContext(ctx, r.q(query), now, userID)
	if err != nil {
		return fmt.Errorf("failed to disable user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}

	return nil
}

// ============================================================================
// IncrementFailedLoginCount - Increments failed login count and updates last failed login timestamp
// Used for tracking failed login attempts before account lockout
// ============================================================================
func (r *Repository) IncrementFailedLoginCount(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE {{schema}}.users
		SET
			failed_login_count = failed_login_count + 1,
			last_failed_login = $1,
			updated_at = $1
		WHERE id = $2
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to increment failed login count: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}

	return nil
}

// ============================================================================
// RegisterFailedLogin - Atomically records a failed login attempt and, if the
// post-increment count reaches maxAttempts, locks the account — all in a single
// UPDATE ... RETURNING. This makes the lockout decision against the authoritative
// DB count instead of a value read at the start of the request, so concurrent
// failed logins can no longer trip the lock one attempt early or late.
// maxAttempts <= 0 disables auto-lock (the count is still incremented). Returns
// the new failed_login_count and whether the account is now locked. It never
// clears an existing lock.
// ============================================================================
func (r *Repository) RegisterFailedLogin(ctx context.Context, userID uuid.UUID, maxAttempts int, lockDuration time.Duration) (int, bool, error) {
	now := time.Now()
	lockedUntil := now.Add(lockDuration)
	query := `
		UPDATE {{schema}}.users
		SET
			failed_login_count = failed_login_count + 1,
			last_failed_login = $1,
			updated_at = $1,
			is_locked = CASE WHEN $2 > 0 AND failed_login_count + 1 >= $2 THEN true ELSE is_locked END,
			locked_until = CASE WHEN $2 > 0 AND failed_login_count + 1 >= $2 THEN $3 ELSE locked_until END
		WHERE id = $4
		RETURNING failed_login_count, is_locked
	`

	var count int
	var locked bool
	err := r.rw.QueryRowContext(ctx, r.q(query), now, maxAttempts, lockedUntil, userID).Scan(&count, &locked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false, fmt.Errorf("user not found: %w", model.ErrNotFound)
		}
		return 0, false, fmt.Errorf("failed to register failed login: %w", err)
	}

	return count, locked, nil
}

// ============================================================================
// Lock - Locks a user account (security control)
// Sets is_locked to true and optionally sets locked_until for auto-unlock
// Also increments failed_login_count to reflect the final failed attempt
// If lockedUntil is nil, the account is locked indefinitely (until admin unlock)
// ============================================================================
func (r *Repository) Lock(ctx context.Context, userID uuid.UUID, lockedUntil *time.Time) error {
	query := `
		UPDATE {{schema}}.users
		SET
			is_locked = true,
			locked_until = $1,
			failed_login_count = failed_login_count + 1,
			last_failed_login = $2,
			updated_at = $2
		WHERE id = $3
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), lockedUntil, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to lock user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}

	return nil
}

// ============================================================================
// Unlock - Unlocks a user account (security control)
// Clears the locked status, locked_until timestamp, and resets failed login count
// ============================================================================
func (r *Repository) Unlock(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE {{schema}}.users
		SET
			is_locked = false,
			locked_until = NULL,
			failed_login_count = 0,
			updated_at = $1
		WHERE id = $2
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to unlock user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}

	return nil
}

// ============================================================================
// UpdateLastLogin - Updates the last login timestamp for a user
// Called after successful authentication to track user activity
// ============================================================================
func (r *Repository) UpdateLastLogin(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE {{schema}}.users
		SET
			last_login = $1,
			updated_at = $1
		WHERE id = $2
	`

	now := time.Now()
	result, err := r.rw.ExecContext(ctx, r.q(query), now, userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}

	return nil
}

// ============================================================================
// ExistsActive - Checks if an active (enabled, unlocked) user exists
// Useful when linking external actors to users
// ============================================================================
func (r *Repository) ExistsActive(ctx context.Context, email, tenantID string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM {{schema}}.users
			WHERE email = $1 AND tenant_id = $2 AND is_enabled = TRUE AND is_locked = FALSE
		)
	`

	var exists bool
	err := r.ro.QueryRowContext(ctx, r.q(query), email, tenantID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if active user exists: %w", err)
	}

	return exists, nil
}

// ============================================================================
// GetDisplayName - Gets just the display name for a user
// Useful when enriching responses with user names
// ============================================================================
func (r *Repository) GetDisplayName(ctx context.Context, userID uuid.UUID) (string, error) {
	query := `SELECT display_name FROM {{schema}}.users WHERE id = $1`

	var displayName string
	err := r.ro.QueryRowContext(ctx, r.q(query), userID).Scan(&displayName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("user not found: %w", model.ErrNotFound)
		}
		return "", fmt.Errorf("failed to get display name: %w", err)
	}

	return displayName, nil
}

// ============================================================================
// GetActiveUserIDByEmail - Gets user ID for an active (enabled, unlocked) user
// Useful when linking external actors to users by email
// ============================================================================
func (r *Repository) GetActiveUserIDByEmail(ctx context.Context, email, tenantID string) (uuid.UUID, error) {
	query := `
		SELECT id FROM {{schema}}.users
		WHERE email = $1 AND tenant_id = $2 AND is_enabled = TRUE AND is_locked = FALSE
		LIMIT 1
	`

	var userID uuid.UUID
	err := r.ro.QueryRowContext(ctx, r.q(query), email, tenantID).Scan(&userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return uuid.Nil, fmt.Errorf("active user not found for email: %w", model.ErrNotFound)
		}
		return uuid.Nil, fmt.Errorf("failed to get active user ID: %w", err)
	}

	return userID, nil
}

// ============================================================================
// CountUsersByTenant - Returns the count of users in a tenant
// ============================================================================
func (r *Repository) CountUsersByTenant(ctx context.Context, tenantID string) (int, error) {
	query := `SELECT COUNT(*) FROM {{schema}}.users WHERE tenant_id = $1`

	var count int
	err := r.ro.QueryRowContext(ctx, r.q(query), tenantID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}

	return count, nil
}

// ============================================================================
// UpdateRolesByTenant - Updates user roles with tenant isolation
// Validates that the user belongs to the specified tenant before updating.
// Bumps token_version so any already-issued access tokens (which embed roles in
// their claims) are rejected by ValidateJWT; the next refresh re-reads the new
// roles. This prevents a downgraded user from retaining elevated roles in a live
// access token until it expires.
// ============================================================================
func (r *Repository) UpdateRolesByTenant(ctx context.Context, userID uuid.UUID, tenantID string, roles []string) error {
	rolesJSON, err := json.Marshal(roles)
	if err != nil {
		return fmt.Errorf("failed to marshal roles: %w", err)
	}

	query := `
		UPDATE {{schema}}.users
		SET
			roles = $1,
			token_version = token_version + 1,
			updated_at = $2
		WHERE id = $3 AND tenant_id = $4
	`

	result, err := r.rw.ExecContext(ctx, r.q(query),
		rolesJSON,
		time.Now(),
		userID,
		tenantID,
	)
	if err != nil {
		return fmt.Errorf("failed to update user roles: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found or does not belong to tenant")
	}

	return nil
}

// ============================================================================
// EnableByTenant - Enables a user account with tenant isolation
// Validates tenant ownership before enabling
// ============================================================================
func (r *Repository) EnableByTenant(ctx context.Context, userID uuid.UUID, tenantID string) error {
	query := `
		UPDATE {{schema}}.users
		SET
			is_enabled = true,
			disabled_at = NULL,
			updated_at = $1
		WHERE id = $2 AND tenant_id = $3
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), time.Now(), userID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to enable user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found or does not belong to tenant: %w", model.ErrNotFound)
	}

	return nil
}

// ============================================================================
// UpdateByTenant - Updates a user's display_name and roles with tenant isolation.
// Bumps token_version so already-issued access tokens (which embed roles) are
// rejected by ValidateJWT; the next refresh re-reads the updated roles. This
// keeps a role change from leaving stale roles in a live access token.
// ============================================================================
func (r *Repository) UpdateByTenant(ctx context.Context, userID uuid.UUID, tenantID string, req model.UpdateUserRequest) error {
	rolesJSON, err := json.Marshal(req.Roles)
	if err != nil {
		return fmt.Errorf("failed to marshal roles: %w", err)
	}

	query := `
		UPDATE {{schema}}.users
		SET display_name = $1, roles = $2, token_version = token_version + 1, updated_at = $3
		WHERE id = $4 AND tenant_id = $5
	`
	result, err := r.rw.ExecContext(ctx, r.q(query), req.DisplayName, rolesJSON, time.Now(), userID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return rowsAffectedOrNotFound(result)
}

// ============================================================================
// SetPasswordByTenant - Sets the password hash with tenant isolation
// ============================================================================
func (r *Repository) SetPasswordByTenant(ctx context.Context, userID uuid.UUID, tenantID, hashedPassword string) error {
	query := `
		UPDATE {{schema}}.users
		SET password_hash = $1, updated_at = $2
		WHERE id = $3 AND tenant_id = $4
	`
	result, err := r.rw.ExecContext(ctx, r.q(query), hashedPassword, time.Now(), userID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to set password: %w", err)
	}
	return rowsAffectedOrNotFound(result)
}

// ============================================================================
// DeleteByTenant - Soft deletes a user with tenant isolation
// ============================================================================
func (r *Repository) DeleteByTenant(ctx context.Context, userID uuid.UUID, tenantID string) error {
	query := `
		UPDATE {{schema}}.users
		SET is_enabled = false, disabled_at = $1, updated_at = $1
		WHERE id = $2 AND tenant_id = $3
	`
	now := time.Now()
	result, err := r.rw.ExecContext(ctx, r.q(query), now, userID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to soft delete user: %w", err)
	}
	return rowsAffectedOrNotFound(result)
}

// ============================================================================
// LockByTenant - Locks a user account with tenant isolation
// ============================================================================
func (r *Repository) LockByTenant(ctx context.Context, userID uuid.UUID, tenantID string, lockedUntil *time.Time) error {
	query := `
		UPDATE {{schema}}.users
		SET is_locked = true, locked_until = $1, updated_at = $2
		WHERE id = $3 AND tenant_id = $4
	`
	result, err := r.rw.ExecContext(ctx, r.q(query), lockedUntil, time.Now(), userID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to lock user: %w", err)
	}
	return rowsAffectedOrNotFound(result)
}

// ============================================================================
// UnlockByTenant - Unlocks a user account with tenant isolation
// ============================================================================
func (r *Repository) UnlockByTenant(ctx context.Context, userID uuid.UUID, tenantID string) error {
	query := `
		UPDATE {{schema}}.users
		SET is_locked = false, locked_until = NULL, failed_login_count = 0, updated_at = $1
		WHERE id = $2 AND tenant_id = $3
	`
	result, err := r.rw.ExecContext(ctx, r.q(query), time.Now(), userID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to unlock user: %w", err)
	}
	return rowsAffectedOrNotFound(result)
}

// ============================================================================
// IncrementTokenVersionByTenant - Bumps token_version with tenant isolation
// ============================================================================
func (r *Repository) IncrementTokenVersionByTenant(ctx context.Context, userID uuid.UUID, tenantID string) error {
	query := `
		UPDATE {{schema}}.users
		SET token_version = token_version + 1, updated_at = $1
		WHERE id = $2 AND tenant_id = $3
	`
	result, err := r.rw.ExecContext(ctx, r.q(query), time.Now(), userID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to increment token version: %w", err)
	}
	return rowsAffectedOrNotFound(result)
}

// rowsAffectedOrNotFound returns model.ErrNotFound when a tenant-scoped mutation
// matched no row (unknown user or wrong tenant), and surfaces RowsAffected errors.
func rowsAffectedOrNotFound(result sql.Result) error {
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("user not found or does not belong to tenant: %w", model.ErrNotFound)
	}
	return nil
}

// ============================================================================
// DisableByTenant - Disables a user account with tenant isolation
// Validates tenant ownership and increments token_version to invalidate JWTs
// ============================================================================
func (r *Repository) DisableByTenant(ctx context.Context, userID uuid.UUID, tenantID string) error {
	query := `
		UPDATE {{schema}}.users
		SET
			is_enabled = false,
			disabled_at = $1,
			token_version = token_version + 1,
			updated_at = $1
		WHERE id = $2 AND tenant_id = $3
	`

	now := time.Now()
	result, err := r.rw.ExecContext(ctx, r.q(query), now, userID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to disable user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found or does not belong to tenant")
	}

	return nil
}
