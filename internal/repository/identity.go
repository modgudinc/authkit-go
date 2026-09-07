// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	uuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/modgudinc/authkit-go/model"
)

// Identity Repository Methods (users is the GLOBAL identity — no tenant_id, no
// roles; per-tenant access lives on memberships, see membership.go):
//
// User Management:
// - Create        - Creates a new global user with default status (enabled, unlocked)
// - Update        - Updates the user's display_name only
// - Delete        - Soft deletes a user (sets is_enabled=false)
//
// Password Management:
// - SetPassword    - Sets the password hash (accepts hashed password only)
// - VerifyPassword - Retrieves the password hash for verification
//
// Query Methods (keyed by global user id or globally-unique email):
// - GetByID       - Retrieves a user by ID
// - GetByEmail    - Retrieves a user by email (case-insensitive, globally unique)
// - Exists        - Checks whether a user exists for an email
// - List          - Lists users with pagination
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
// - IncrementTokenVersion - Invalidates all of the identity's existing access tokens

// ============================================================================
// Create - Creates a new global user with default status (enabled, unlocked)
// ============================================================================
func (r *Repository) Create(ctx context.Context, user model.CreateUserRequest) (string, error) {
	gen, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("could not generate an id for user: %w", err)
	}
	userID := gen.String()

	now := time.Now()

	query := `
		INSERT INTO {{schema}}.users (
			id, email, password_hash, display_name, token_version,
			is_enabled, is_locked, failed_login_count,
			created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err = r.rw.ExecContext(ctx, r.q(query),
		userID,
		user.Email,
		user.PasswordHash,
		user.DisplayName,
		0,     // token_version (default)
		true,  // is_enabled (default: enabled)
		false, // is_locked (default: not locked)
		0,     // failed_login_count (default: 0)
		now,   // created_at
		now,   // updated_at
	)
	if err != nil {
		// A lower(email) uniqueness conflict means an identity already exists for
		// this email globally; surface a clean sentinel instead of the raw
		// driver/constraint string so callers can errors.Is it.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return "", fmt.Errorf("user already exists for this email: %w", model.ErrUserExists)
		}
		return "", fmt.Errorf("failed to create user: %w", err)
	}

	return userID, nil
}

// ============================================================================
// VerifyPassword - Retrieves the stored password hash for verification.
// IMPORTANT: Returns the HASHED password for comparison at service layer.
// Password verification (hash comparison) must be done at service/controller layer.
//
// Reads from the PRIMARY (rw), not a read replica: this hash backs a
// security-sensitive auth gate (e.g. ChangePassword's old-password check), and a
// lagging replica could return a stale hash right after a password change. This
// matches the read-write split's rule that validation paths use the primary.
// ============================================================================
func (r *Repository) VerifyPassword(ctx context.Context, userID string) (string, error) {
	query := `
		SELECT password_hash
		FROM {{schema}}.users
		WHERE id = $1
	`

	var hashedPassword string
	err := r.rw.QueryRowContext(ctx, r.q(query), userID).Scan(&hashedPassword)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("user not found: %w", model.ErrNotFound)
		}
		return "", fmt.Errorf("failed to get password hash: %w", err)
	}

	return hashedPassword, nil
}

// rowQuerier is the single-row read surface shared by the rw (primary) and ro
// (replica) *sql.DB handles, so a query helper can run against either one.
type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// scannable is the row-scan surface shared by *sql.Row (single-row queries) and
// *sql.Rows (result-set iteration), so scanUser/scanMembership can scan from either.
type scannable interface {
	Scan(dest ...any) error
}

// userColumns is the SELECT list, in Scan order, for a full user row. Keeping the
// column list and the scan together (here + scanUser) means a column add/reorder is
// one edit, not several parallel ones that must stay in lockstep.
const userColumns = "id, email, password_hash, display_name, token_version, " +
	"is_enabled, disabled_at, is_locked, locked_until, failed_login_count, last_failed_login, last_login, " +
	"created_at, updated_at"

// scanUser scans a full user row (the userColumns, in order) from row, including the
// nullable timestamp fields. It returns the raw scan error so callers can map
// sql.ErrNoRows to their own not-found message.
func scanUser(row scannable) (*model.User, error) {
	var user model.User
	var disabledAt, lockedUntil, lastFailedLogin, lastLogin *time.Time

	if err := row.Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.DisplayName,
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
	); err != nil {
		return nil, err
	}

	user.DisabledAt = disabledAt
	user.LockedUntil = lockedUntil
	user.LastFailedLoginAt = lastFailedLogin
	user.LastLoginAt = lastLogin

	return &user, nil
}

// ============================================================================
// getByID - Global user lookup by id against the supplied handle (rw or ro).
// Shared by GetByID (replica) and GetByIDFromPrimary (primary).
// ============================================================================
func (r *Repository) getByID(ctx context.Context, db rowQuerier, userID string) (*model.User, error) {
	query := `SELECT ` + userColumns + ` FROM {{schema}}.users WHERE id = $1`

	user, err := scanUser(db.QueryRowContext(ctx, r.q(query), userID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user not found: %w", model.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}
	return user, nil
}

// ============================================================================
// GetByID - Retrieves a user by ID. Reads from the read replica (ro) — use
// GetByIDFromPrimary for security gates that must observe the latest writes.
// ============================================================================
func (r *Repository) GetByID(ctx context.Context, userID string) (*model.User, error) {
	return r.getByID(ctx, r.ro, userID)
}

// ============================================================================
// GetByIDFromPrimary - Like GetByID but reads from the PRIMARY (rw).
//
// It backs the JWT-validation security gate (AuthService.ValidateJWT), where
// token_version, is_enabled and is_locked must reflect the latest writes
// immediately: LogoutAll / ChangePassword bump token_version, and disable/lock
// write to rw. A lagging replica would otherwise let a just-revoked token (or a
// just-disabled/locked account) keep passing validation for the replication-lag
// window — a fail-open gap. This mirrors the same rw decision made for
// GetByTokenHash and GetAPIKeyByHash.
// ============================================================================
func (r *Repository) GetByIDFromPrimary(ctx context.Context, userID string) (*model.User, error) {
	return r.getByID(ctx, r.rw, userID)
}

// ============================================================================
// getByEmail - Global user lookup by email (case-insensitive) against the supplied
// handle (rw or ro). Shared by GetByEmail (replica) and GetByEmailFromPrimary
// (primary). Matches on lower(email), served by the users_email_lower_unique index.
// ============================================================================
func (r *Repository) getByEmail(ctx context.Context, db rowQuerier, email string) (*model.User, error) {
	query := `SELECT ` + userColumns + ` FROM {{schema}}.users WHERE lower(email) = lower($1)`

	user, err := scanUser(db.QueryRowContext(ctx, r.q(query), email))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user not found: %w", model.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	return user, nil
}

// ============================================================================
// GetByEmail - Retrieves a user by email (case-insensitive; email is globally
// unique). Reads from the read replica (ro) — use GetByEmailFromPrimary for the
// login security gate.
// ============================================================================
func (r *Repository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	return r.getByEmail(ctx, r.ro, email)
}

// ============================================================================
// GetByEmailFromPrimary - Like GetByEmail but reads from the PRIMARY (rw).
//
// It backs AuthService.LoginByEmail/Login, whose is_enabled / is_locked gate must
// observe an admin disable/lock (or an auto-lock from RegisterFailedLogin)
// immediately. A lagging replica would otherwise let a just-disabled/locked account
// pass the front-door gate for the replication-lag window. The authoritative lockout
// counter is already enforced on rw via RegisterFailedLogin, so only this gate read
// needed hardening.
// ============================================================================
func (r *Repository) GetByEmailFromPrimary(ctx context.Context, email string) (*model.User, error) {
	return r.getByEmail(ctx, r.rw, email)
}

// ============================================================================
// Exists - Checks whether a user exists for an email (case-insensitive, global).
// ============================================================================
func (r *Repository) Exists(ctx context.Context, email string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1
			FROM {{schema}}.users
			WHERE lower(email) = lower($1)
		)
	`

	var exists bool
	err := r.ro.QueryRowContext(ctx, r.q(query), email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if user exists: %w", err)
	}

	return exists, nil
}

// ============================================================================
// List - Lists users with pagination, ordered by created_at DESC (newest first).
// This is a global (cross-tenant) admin listing; for a tenant's members use
// ListMembershipsByTenant.
// ============================================================================
func (r *Repository) List(ctx context.Context, limit, offset int) ([]*model.User, error) {
	query := `SELECT ` + userColumns + `
		FROM {{schema}}.users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`

	rows, err := r.ro.QueryContext(ctx, r.q(query), limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var users []*model.User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user row: %w", err)
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user rows: %w", err)
	}

	return users, nil
}

// ============================================================================
// IncrementFailedLoginCount - Increments the failed login count and updates the
// last-failed-login timestamp for a user. Used for tracking failed login attempts
// before account lockout.
// ============================================================================
func (r *Repository) IncrementFailedLoginCount(ctx context.Context, userID string) error {
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

	return rowsAffectedOrNotFound(result)
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
func (r *Repository) RegisterFailedLogin(ctx context.Context, userID string, maxAttempts int, lockDuration time.Duration) (int, bool, error) {
	tx, err := r.rw.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, fmt.Errorf("failed to begin failed-login registration: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Lock the row and capture the pre-update status so a lock transition can be
	// audited (the failed-login lockout was the trigger's 'system' lock case).
	old, err := r.readUserStatusForUpdate(ctx, tx, userID)
	if err != nil {
		return 0, false, err
	}

	now := time.Now()
	lockedUntil := now.Add(lockDuration)
	var count int
	var locked bool
	err = tx.QueryRowContext(ctx, r.q(`
		UPDATE {{schema}}.users
		SET
			failed_login_count = failed_login_count + 1,
			last_failed_login = $1,
			updated_at = $1,
			is_locked = CASE WHEN $2 > 0 AND failed_login_count + 1 >= $2 THEN true ELSE is_locked END,
			locked_until = CASE WHEN $2 > 0 AND failed_login_count + 1 >= $2 THEN $3 ELSE locked_until END
		WHERE id = $4
		RETURNING failed_login_count, is_locked
	`), now, maxAttempts, lockedUntil, userID).Scan(&count, &locked)
	if err != nil {
		return 0, false, fmt.Errorf("failed to register failed login: %w", err)
	}

	current := old
	current.FailedLoginCount = count
	current.LastFailedLogin = &now
	current.IsLocked = locked
	if locked && !old.IsLocked {
		current.LockedUntil = &lockedUntil
	}
	// The automatic failed-login lockout is the only system-attributed status
	// change; every explicit admin mutation goes through withUserStatusAudit with
	// actorAdmin.
	if err := r.recordStatusChange(ctx, tx, userID, old, current, actorSystem); err != nil {
		return 0, false, err
	}

	if err := tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("failed to commit failed-login registration: %w", err)
	}
	committed = true
	return count, locked, nil
}

// ============================================================================
// UpdateLastLogin - Updates the last login timestamp for a user. Called after
// successful authentication to track user activity.
// ============================================================================
func (r *Repository) UpdateLastLogin(ctx context.Context, userID string) error {
	query := `
		UPDATE {{schema}}.users
		SET
			last_login = $1,
			updated_at = $1
		WHERE id = $2
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return rowsAffectedOrNotFound(result)
}

// ============================================================================
// ExistsActive - Checks whether an active (enabled, unlocked) user exists for an
// email. Useful when linking external actors to users.
// ============================================================================
func (r *Repository) ExistsActive(ctx context.Context, email string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM {{schema}}.users
			WHERE lower(email) = lower($1) AND is_enabled = TRUE AND is_locked = FALSE
		)
	`

	var exists bool
	err := r.ro.QueryRowContext(ctx, r.q(query), email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if active user exists: %w", err)
	}

	return exists, nil
}

// ============================================================================
// GetDisplayName - Gets just the display name for a user. Useful when enriching
// responses with user names.
// ============================================================================
func (r *Repository) GetDisplayName(ctx context.Context, userID string) (string, error) {
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
// GetActiveUserIDByEmail - Gets the user ID for an active (enabled, unlocked) user
// by email. Useful when linking external actors to users by email.
// ============================================================================
func (r *Repository) GetActiveUserIDByEmail(ctx context.Context, email string) (string, error) {
	query := `
		SELECT id FROM {{schema}}.users
		WHERE lower(email) = lower($1) AND is_enabled = TRUE AND is_locked = FALSE
		LIMIT 1
	`

	var userID string
	err := r.ro.QueryRowContext(ctx, r.q(query), email).Scan(&userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("active user not found for email: %w", model.ErrNotFound)
		}
		return "", fmt.Errorf("failed to get active user ID: %w", err)
	}

	return userID, nil
}

// ============================================================================
// Update - Updates a user's display_name. Identity-level (keyed by user id);
// roles are no longer here — they are per-tenant (UpdateMembershipRoles). A
// display-name-only edit must not invalidate access tokens, so token_version is
// untouched.
// ============================================================================
func (r *Repository) Update(ctx context.Context, userID string, req model.UpdateUserRequest) error {
	// COALESCE leaves display_name unchanged when DisplayName is nil, enabling a
	// partial update.
	query := `
		UPDATE {{schema}}.users
		SET display_name = COALESCE($1, display_name),
		    updated_at = $2
		WHERE id = $3
	`
	result, err := r.rw.ExecContext(ctx, r.q(query), req.DisplayName, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return rowsAffectedOrNotFound(result)
}

// ============================================================================
// SetPassword - Sets the password hash for a user.
// ============================================================================
func (r *Repository) SetPassword(ctx context.Context, userID, hashedPassword string) error {
	query := `
		UPDATE {{schema}}.users
		SET password_hash = $1, updated_at = $2
		WHERE id = $3
	`
	result, err := r.rw.ExecContext(ctx, r.q(query), hashedPassword, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to set password: %w", err)
	}
	return rowsAffectedOrNotFound(result)
}

// ============================================================================
// SetPasswordAndBumpTokenVersion - Sets the password hash AND increments
// token_version in a single UPDATE. Used by ChangePassword so the password change
// and the access-token invalidation (token_version) are applied atomically: they can
// never be left half-applied (password changed but old JWTs still valid, or vice
// versa). Refresh-token revocation remains a separate step. token_version is the
// IDENTITY version, so this invalidates every workspace's access tokens.
// ============================================================================
func (r *Repository) SetPasswordAndBumpTokenVersion(ctx context.Context, userID, hashedPassword string) error {
	query := `
		UPDATE {{schema}}.users
		SET password_hash = $1, token_version = token_version + 1, updated_at = $2
		WHERE id = $3
	`
	result, err := r.rw.ExecContext(ctx, r.q(query), hashedPassword, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to set password and bump token version: %w", err)
	}
	return rowsAffectedOrNotFound(result)
}

// ============================================================================
// Delete - Soft deletes a user (sets is_enabled=false).
// ============================================================================
func (r *Repository) Delete(ctx context.Context, userID string) error {
	return r.withUserStatusAudit(ctx, userID, actorAdmin, func(ctx context.Context, tx *sql.Tx, old userStatusSnapshot) (userStatusSnapshot, error) {
		now := time.Now()
		if _, err := tx.ExecContext(ctx, r.q(`
			UPDATE {{schema}}.users SET is_enabled = false, disabled_at = $1, updated_at = $1 WHERE id = $2
		`), now, userID); err != nil {
			return old, fmt.Errorf("failed to soft delete user: %w", err)
		}
		current := old
		current.IsEnabled = false
		current.DisabledAt = &now
		return current, nil
	})
}

// ============================================================================
// Enable - Enables a disabled user account.
// ============================================================================
func (r *Repository) Enable(ctx context.Context, userID string) error {
	return r.withUserStatusAudit(ctx, userID, actorAdmin, func(ctx context.Context, tx *sql.Tx, old userStatusSnapshot) (userStatusSnapshot, error) {
		if _, err := tx.ExecContext(ctx, r.q(`
			UPDATE {{schema}}.users SET is_enabled = true, disabled_at = NULL, updated_at = $1 WHERE id = $2
		`), time.Now(), userID); err != nil {
			return old, fmt.Errorf("failed to enable user: %w", err)
		}
		current := old
		current.IsEnabled = true
		current.DisabledAt = nil
		return current, nil
	})
}

// ============================================================================
// Disable - Disables a user account and increments token_version to invalidate the
// identity's access tokens (every workspace).
// ============================================================================
func (r *Repository) Disable(ctx context.Context, userID string) error {
	return r.withUserStatusAudit(ctx, userID, actorAdmin, func(ctx context.Context, tx *sql.Tx, old userStatusSnapshot) (userStatusSnapshot, error) {
		now := time.Now()
		if _, err := tx.ExecContext(ctx, r.q(`
			UPDATE {{schema}}.users
			SET is_enabled = false, disabled_at = $1, token_version = token_version + 1, updated_at = $1
			WHERE id = $2
		`), now, userID); err != nil {
			return old, fmt.Errorf("failed to disable user: %w", err)
		}
		current := old
		current.IsEnabled = false
		current.DisabledAt = &now
		return current, nil
	})
}

// ============================================================================
// Lock - Locks a user account with an optional auto-unlock time.
// ============================================================================
func (r *Repository) Lock(ctx context.Context, userID string, lockedUntil *time.Time) error {
	return r.withUserStatusAudit(ctx, userID, actorAdmin, func(ctx context.Context, tx *sql.Tx, old userStatusSnapshot) (userStatusSnapshot, error) {
		if _, err := tx.ExecContext(ctx, r.q(`
			UPDATE {{schema}}.users SET is_locked = true, locked_until = $1, updated_at = $2 WHERE id = $3
		`), lockedUntil, time.Now(), userID); err != nil {
			return old, fmt.Errorf("failed to lock user: %w", err)
		}
		current := old
		current.IsLocked = true
		current.LockedUntil = lockedUntil
		return current, nil
	})
}

// ============================================================================
// Unlock - Unlocks a user account and resets the failed-login count.
// ============================================================================
func (r *Repository) Unlock(ctx context.Context, userID string) error {
	return r.withUserStatusAudit(ctx, userID, actorAdmin, func(ctx context.Context, tx *sql.Tx, old userStatusSnapshot) (userStatusSnapshot, error) {
		if _, err := tx.ExecContext(ctx, r.q(`
			UPDATE {{schema}}.users SET is_locked = false, locked_until = NULL, failed_login_count = 0, updated_at = $1 WHERE id = $2
		`), time.Now(), userID); err != nil {
			return old, fmt.Errorf("failed to unlock user: %w", err)
		}
		current := old
		current.IsLocked = false
		current.LockedUntil = nil
		current.FailedLoginCount = 0
		return current, nil
	})
}

// ============================================================================
// IncrementTokenVersion - Bumps the identity's token_version, invalidating all of
// its existing access tokens (every workspace). Backs LogoutAll.
// ============================================================================
func (r *Repository) IncrementTokenVersion(ctx context.Context, userID string) error {
	query := `
		UPDATE {{schema}}.users
		SET token_version = token_version + 1, updated_at = $1
		WHERE id = $2
	`
	result, err := r.rw.ExecContext(ctx, r.q(query), time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to increment token version: %w", err)
	}
	return rowsAffectedOrNotFound(result)
}

// rowsAffectedOrNotFound returns model.ErrNotFound when a user mutation matched no
// row (unknown user id), and surfaces RowsAffected errors.
func rowsAffectedOrNotFound(result sql.Result) error {
	return requireRowsAffected(result, fmt.Errorf("user not found: %w", model.ErrNotFound))
}
