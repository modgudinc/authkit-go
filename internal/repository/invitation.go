// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/modgudinc/authkit-go/model"
)

// uniqueViolation is the PostgreSQL SQLSTATE for a unique_violation (23505).
const uniqueViolation = "23505"

// Invitation Repository Methods:
//
// Invitation Management:
// - CreateInvitation        - Creates a new invitation for team member signup
// - GetInvitation           - Retrieves an invitation by code
// - ListInvitations         - Lists all invitations for a tenant
// - ListActiveInvitations   - Lists active (not expired, not fully used) invitations
// - DeleteInvitation        - Deletes an invitation by code
//
// Invitation Validation:
// - IsValid                 - Checks if an invitation is valid (not expired, has uses remaining)
// - HasPending              - Checks if an active invitation exists for an email
//
// Invitation Usage:
// - IncrementUseCount       - Increments the use count after successful signup
// - InvalidateInvitation    - Invalidates an invitation (sets current_uses = max_uses)
//
// Maintenance:
// - CleanupExpired          - Cleanup method to remove expired invitations

// InsertInvitationParams contains the data needed to insert a new invitation. It
// is a repository-internal persistence DTO — callers use
// InvitationService.CreateInvitation with model.CreateInvitationRequest, which the
// service maps onto this type (generating the code and resolving defaults).
type InsertInvitationParams struct {
	Code      string
	TenantID  string
	CreatedBy string
	Roles     []string
	Email     string
	ExpiresAt time.Time
	MaxUses   int
}

// ============================================================================
// CreateInvitation - Creates a new invitation for team member signup
// ============================================================================
func (r *Repository) CreateInvitation(ctx context.Context, params InsertInvitationParams) error {
	query := `
		INSERT INTO {{schema}}.invitations (
			code, tenant_id, created_by, roles, email, expires_at, max_uses, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
	`

	// Marshal roles to JSON for JSONB column
	rolesJSON, err := json.Marshal(params.Roles)
	if err != nil {
		return fmt.Errorf("failed to marshal roles: %w", err)
	}

	_, err = r.rw.ExecContext(ctx, r.q(query),
		params.Code,
		params.TenantID,
		params.CreatedBy,
		rolesJSON,
		params.Email,
		params.ExpiresAt,
		params.MaxUses,
	)
	if err != nil {
		// code is the primary key and is server-minted from crypto/rand, so a
		// unique violation here is an astronomically rare internal collision, not a
		// caller error. Surface a generic sentinel instead of leaking the raw
		// constraint string, matching the other writers.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return fmt.Errorf("invitation code collision: %w", model.ErrInternal)
		}
		return fmt.Errorf("failed to create invitation: %w", err)
	}

	return nil
}

// ============================================================================
// GetInvitation - Retrieves an invitation by code
// ============================================================================
func (r *Repository) GetInvitation(ctx context.Context, code string) (*model.Invitation, error) {
	query := `
		SELECT code, tenant_id, created_by, roles, email, expires_at, max_uses, current_uses, created_at
		FROM {{schema}}.invitations
		WHERE code = $1
	`

	var invitation model.Invitation
	var rolesJSON []byte
	err := r.ro.QueryRowContext(ctx, r.q(query), code).Scan(
		&invitation.Code,
		&invitation.TenantID,
		&invitation.CreatedBy,
		&rolesJSON,
		&invitation.Email,
		&invitation.ExpiresAt,
		&invitation.MaxUses,
		&invitation.CurrentUses,
		&invitation.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("invitation not found: %w", model.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get invitation: %w", err)
	}

	// Unmarshal roles from JSONB
	if err := json.Unmarshal(rolesJSON, &invitation.Roles); err != nil {
		return nil, fmt.Errorf("failed to unmarshal roles: %w", err)
	}

	return &invitation, nil
}

// ============================================================================
// IsValid - Checks if an invitation is valid (not expired and has uses remaining)
// Returns true if valid, false otherwise with an error message
// ============================================================================
func (r *Repository) IsValid(invitation *model.Invitation) (bool, error) {
	// Check if expired
	if time.Now().After(invitation.ExpiresAt) {
		return false, fmt.Errorf("invitation has expired: %w", model.ErrInvitationInvalid)
	}

	// Check if uses exhausted
	if invitation.CurrentUses >= invitation.MaxUses {
		return false, fmt.Errorf("invitation has been fully used (%d/%d): %w", invitation.CurrentUses, invitation.MaxUses, model.ErrInvitationInvalid)
	}

	return true, nil
}

// ============================================================================
// IncrementUseCount - Increments the use count for an invitation
// Called after successful user signup with this invitation
// Automatically prevents exceeding max_uses via SQL constraint
// ============================================================================
func (r *Repository) IncrementUseCount(ctx context.Context, code string) error {
	query := `
		UPDATE {{schema}}.invitations
		SET current_uses = current_uses + 1
		WHERE code = $1
		  AND current_uses < max_uses  -- Ensure we don't exceed max uses
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), code)
	if err != nil {
		return fmt.Errorf("failed to increment invitation use count: %w", err)
	}

	return requireRowsAffected(result, fmt.Errorf("invitation %q not found or max uses exceeded: %w", code, model.ErrInvitationInvalid))
}

// ============================================================================
// AcceptInvitation - Atomically redeems an invitation, resolving the invitee's
// GLOBAL identity and granting the invited membership.
//
// In a single transaction it locks the invitation row, validates it (not expired,
// uses remaining, and the supplied email matches the invitation's target email),
// increments current_uses under the max_uses guard, then:
//   - reuses the existing global user when one already exists for the email (the
//     invitee keeps their single identity/password — no second account/password), or
//   - creates a new global user from the supplied displayName/passwordHash; and
//   - upserts a membership to the invitation's tenant with the invitation's roles.
//
// Performing all of this in one transaction closes the validate-then-use TOCTOU
// window that would let a single-use invitation onboard more than once, and binds
// the grant to the invitation's intended email and roles (no role/privilege hijack).
//
// Returns the resolved user's ID and whether a NEW identity was created (false when
// an existing one was reused). displayName/passwordHash are used only when creating
// a new identity; for a reused identity they are ignored.
// ============================================================================
func (r *Repository) AcceptInvitation(ctx context.Context, code, email, displayName, passwordHash string) (userID string, created bool, err error) {
	tx, err := r.rw.BeginTx(ctx, nil)
	if err != nil {
		return "", false, fmt.Errorf("failed to begin invitation acceptance: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Lock the invitation row for the duration of the transaction.
	var tenantID, invitedEmail string
	var rolesJSON []byte
	var expiresAt time.Time
	var maxUses, currentUses int
	lookup := `
		SELECT tenant_id, roles, email, expires_at, max_uses, current_uses
		FROM {{schema}}.invitations
		WHERE code = $1
		FOR UPDATE
	`
	if err := tx.QueryRowContext(ctx, r.q(lookup), code).Scan(&tenantID, &rolesJSON, &invitedEmail, &expiresAt, &maxUses, &currentUses); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, fmt.Errorf("invitation not found: %w", model.ErrInvitationInvalid)
		}
		return "", false, fmt.Errorf("failed to load invitation: %w", err)
	}

	// Validate expiry and remaining uses.
	if time.Now().After(expiresAt) {
		return "", false, fmt.Errorf("invitation has expired: %w", model.ErrInvitationInvalid)
	}
	if currentUses >= maxUses {
		return "", false, fmt.Errorf("invitation has been fully used: %w", model.ErrInvitationInvalid)
	}

	// Bind the redemption to the invitation's target email.
	normEmail := strings.ToLower(strings.TrimSpace(email))
	if !strings.EqualFold(strings.TrimSpace(invitedEmail), normEmail) {
		return "", false, fmt.Errorf("email does not match invitation: %w", model.ErrInvitationInvalid)
	}

	var roles []string
	if err := json.Unmarshal(rolesJSON, &roles); err != nil {
		return "", false, fmt.Errorf("failed to unmarshal invitation roles: %w", err)
	}

	// Consume one use under the max_uses guard (defends against a concurrent race
	// even though the row is locked, and keeps the invariant explicit).
	res, err := tx.ExecContext(ctx, r.q(`
		UPDATE {{schema}}.invitations
		SET current_uses = current_uses + 1
		WHERE code = $1 AND current_uses < max_uses
	`), code)
	if err != nil {
		return "", false, fmt.Errorf("failed to consume invitation: %w", err)
	}
	if err := requireRowsAffected(res, fmt.Errorf("invitation has been fully used: %w", model.ErrInvitationInvalid)); err != nil {
		return "", false, err
	}

	// Resolve the invitee's GLOBAL identity: reuse an existing user for this email,
	// else create one. The lookup runs in the same transaction, so a concurrent
	// signup is either already visible here or conflicts on the insert below.
	err = tx.QueryRowContext(ctx, r.q(`SELECT id FROM {{schema}}.users WHERE lower(email) = lower($1)`), normEmail).Scan(&userID)
	switch {
	case err == nil:
		// Existing identity — reuse it; displayName/passwordHash are ignored.
		created = false
	case errors.Is(err, sql.ErrNoRows):
		gen, gerr := uuid.NewV7()
		if gerr != nil {
			return "", false, fmt.Errorf("could not generate an id for user: %w", gerr)
		}
		userID = gen.String()
		now := time.Now()
		insertUser := `
			INSERT INTO {{schema}}.users (
				id, email, password_hash, display_name, token_version,
				is_enabled, is_locked, failed_login_count, created_at, updated_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`
		if _, ierr := tx.ExecContext(ctx, r.q(insertUser),
			userID, normEmail, passwordHash, displayName,
			0, true, false, 0, now, now,
		); ierr != nil {
			// A lower(email) uniqueness conflict means another transaction created the
			// identity between our SELECT and INSERT; surface a clean sentinel. The
			// deferred rollback leaves the invitation unconsumed.
			var pgErr *pgconn.PgError
			if errors.As(ierr, &pgErr) && pgErr.Code == uniqueViolation {
				return "", false, fmt.Errorf("user already exists for this email: %w", model.ErrUserExists)
			}
			return "", false, fmt.Errorf("failed to create user from invitation: %w", ierr)
		}
		created = true
	default:
		return "", false, fmt.Errorf("failed to resolve invitee identity: %w", err)
	}

	// Grant the invited membership (roles from the invitation) to the resolved
	// identity. Idempotent: re-accepting refreshes the roles for that tenant.
	if err := r.upsertMembership(ctx, tx, userID, tenantID, roles); err != nil {
		return "", false, fmt.Errorf("failed to grant invited membership: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return "", false, fmt.Errorf("failed to commit invitation acceptance: %w", err)
	}
	committed = true

	return userID, created, nil
}

// ============================================================================
// InvalidateInvitation - Invalidates an invitation by setting current_uses to max_uses
// Used to revoke an invitation without deleting it (preserves audit trail)
// ============================================================================
func (r *Repository) InvalidateInvitation(ctx context.Context, code string) error {
	query := `
		UPDATE {{schema}}.invitations
		SET current_uses = max_uses
		WHERE code = $1
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), code)
	if err != nil {
		return fmt.Errorf("failed to invalidate invitation: %w", err)
	}

	return requireRowsAffected(result, fmt.Errorf("invitation %q not found: %w", code, model.ErrNotFound))
}

// ============================================================================
// ListInvitations - Lists all invitations for a tenant
// Ordered by created_at DESC (newest first)
// Includes expired and fully used invitations
// ============================================================================
func (r *Repository) ListInvitations(ctx context.Context, tenantID string) ([]*model.Invitation, error) {
	query := `
		SELECT code, tenant_id, created_by, roles, email, expires_at, max_uses, current_uses, created_at
		FROM {{schema}}.invitations
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.ro.QueryContext(ctx, r.q(query), tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list invitations: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var invitations []*model.Invitation
	for rows.Next() {
		var invitation model.Invitation
		var rolesJSON []byte
		err := rows.Scan(
			&invitation.Code,
			&invitation.TenantID,
			&invitation.CreatedBy,
			&rolesJSON,
			&invitation.Email,
			&invitation.ExpiresAt,
			&invitation.MaxUses,
			&invitation.CurrentUses,
			&invitation.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan invitation row: %w", err)
		}

		// Unmarshal roles from JSONB
		if err := json.Unmarshal(rolesJSON, &invitation.Roles); err != nil {
			return nil, fmt.Errorf("failed to unmarshal roles: %w", err)
		}

		invitations = append(invitations, &invitation)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating invitation rows: %w", err)
	}

	return invitations, nil
}

// ============================================================================
// ListActiveInvitations - Lists active (not expired, not fully used) invitations for a tenant
// Ordered by created_at DESC (newest first)
// Filters out expired and fully used invitations at the database level
// ============================================================================
func (r *Repository) ListActiveInvitations(ctx context.Context, tenantID string) ([]*model.Invitation, error) {
	query := `
		SELECT code, tenant_id, created_by, roles, email, expires_at, max_uses, current_uses, created_at
		FROM {{schema}}.invitations
		WHERE tenant_id = $1
		  AND expires_at > NOW()
		  AND current_uses < max_uses
		ORDER BY created_at DESC
	`

	rows, err := r.ro.QueryContext(ctx, r.q(query), tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list active invitations: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var invitations []*model.Invitation
	for rows.Next() {
		var invitation model.Invitation
		var rolesJSON []byte
		err := rows.Scan(
			&invitation.Code,
			&invitation.TenantID,
			&invitation.CreatedBy,
			&rolesJSON,
			&invitation.Email,
			&invitation.ExpiresAt,
			&invitation.MaxUses,
			&invitation.CurrentUses,
			&invitation.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan invitation row: %w", err)
		}

		// Unmarshal roles from JSONB
		if err := json.Unmarshal(rolesJSON, &invitation.Roles); err != nil {
			return nil, fmt.Errorf("failed to unmarshal roles: %w", err)
		}

		invitations = append(invitations, &invitation)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating invitation rows: %w", err)
	}

	return invitations, nil
}

// ============================================================================
// DeleteInvitation - Deletes an invitation by code
// Permanently removes the invitation from the database
// ============================================================================
func (r *Repository) DeleteInvitation(ctx context.Context, code string) error {
	query := `DELETE FROM {{schema}}.invitations WHERE code = $1`

	result, err := r.rw.ExecContext(ctx, r.q(query), code)
	if err != nil {
		return fmt.Errorf("failed to delete invitation: %w", err)
	}

	return requireRowsAffected(result, fmt.Errorf("invitation %q not found: %w", code, model.ErrNotFound))
}

// ============================================================================
// CleanupExpired - Cleanup method to remove expired invitations
// Should be run periodically (e.g., via cron job) to maintain database hygiene
// Returns the number of expired invitations deleted
// ============================================================================
func (r *Repository) CleanupExpiredInvitations(ctx context.Context) (int64, error) {
	query := `DELETE FROM {{schema}}.invitations WHERE expires_at < NOW()`

	result, err := r.rw.ExecContext(ctx, r.q(query))
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired invitations: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected, nil
}

// ============================================================================
// HasPending - Checks if there's an active invitation for the email in a tenant
// Useful when checking invitation status for external actors
// Returns true if an active (not expired, not fully used) invitation exists
// ============================================================================
func (r *Repository) HasPending(ctx context.Context, email, tenantID string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM {{schema}}.invitations
			WHERE email = $1
			  AND tenant_id = $2
			  AND current_uses < max_uses
			  AND expires_at > NOW()
		)
	`

	var exists bool
	err := r.ro.QueryRowContext(ctx, r.q(query), email, tenantID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check for pending invitation: %w", err)
	}

	return exists, nil
}
