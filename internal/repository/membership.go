// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/modgudinc/authkit-go/model"
)

// foreignKeyViolation is the PostgreSQL SQLSTATE for a foreign_key_violation
// (23503). A membership write whose user_id/tenant_id has no parent row raises it.
const foreignKeyViolation = "23503"

// Membership Repository Methods — the user<->tenant graph (authkit owns the graph;
// the embedding application interprets the role strings).
//
// Grant / revoke:
// - AddMembership          - Idempotent upsert of (user_id, tenant_id) with roles (re-grants/reactivates)
// - RemoveMembership       - Soft-revoke (status=suspended) and bump the membership token_version
// - UpdateMembershipRoles  - Replace roles and bump the membership token_version
//
// Queries:
// - GetMembership            - One membership (replica)
// - GetMembershipFromPrimary - One membership from the PRIMARY (JWT-validation gate)
// - ListMembershipsByUser    - A user's workspaces
// - ListMembershipsByTenant  - A tenant's members
// - CountMembershipsByTenant - Member count for a tenant
//
// The per-membership token_version invalidates only this workspace's access tokens
// (role change / revoke), independently of the identity-level users.token_version.

// execer is the write surface shared by the rw *sql.DB handle and a *sql.Tx, so the
// membership upsert can run standalone (AddMembership) or inside a larger
// transaction (AcceptInvitation reuses it after resolving/creating the user).
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// membershipColumns is the SELECT list, in scanMembership order, for a full
// membership row. Keeping the list and the scan together means a column add/reorder
// is one edit, not several that must stay in lockstep (mirrors userColumns).
const membershipColumns = "user_id, tenant_id, roles, token_version, status, created_at, updated_at"

// scanMembership scans a full membership row (membershipColumns, in order) from row,
// including the JSONB roles unmarshal. It returns the raw scan error so callers can
// map sql.ErrNoRows to their own not-found message.
func scanMembership(row scannable) (*model.Membership, error) {
	var m model.Membership
	var rolesJSON []byte
	if err := row.Scan(&m.UserID, &m.TenantID, &rolesJSON, &m.TokenVersion, &m.Status, &m.CreatedAt, &m.UpdatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(rolesJSON, &m.Roles); err != nil {
		return nil, fmt.Errorf("failed to unmarshal membership roles: %w", err)
	}
	return &m, nil
}

// upsertMembership inserts or updates a (user_id, tenant_id) membership against the
// supplied execer (the rw handle for AddMembership, or a *sql.Tx for
// AcceptInvitation). It sets status to active and replaces roles, bumping
// token_version only when the effective grant changes — the roles differ OR a
// suspended membership is being reactivated — so a no-op re-grant does not
// needlessly invalidate the workspace's live access tokens. A nil roles slice is
// normalized to an empty JSON array so the column is never JSON null. created_at /
// updated_at are left to the column defaults and the BEFORE UPDATE trigger.
func (r *Repository) upsertMembership(ctx context.Context, ex execer, userID, tenantID string, roles []string) error {
	if roles == nil {
		roles = []string{}
	}
	rolesJSON, err := json.Marshal(roles)
	if err != nil {
		return fmt.Errorf("failed to marshal roles: %w", err)
	}

	query := `
		INSERT INTO {{schema}}.memberships AS m (user_id, tenant_id, roles, status)
		VALUES ($1, $2, $3::jsonb, 'active')
		ON CONFLICT (user_id, tenant_id) DO UPDATE SET
			roles = EXCLUDED.roles,
			status = 'active',
			token_version = m.token_version
				+ CASE WHEN m.roles IS DISTINCT FROM EXCLUDED.roles OR m.status <> 'active'
				       THEN 1 ELSE 0 END
	`
	if _, err := ex.ExecContext(ctx, r.q(query), userID, tenantID, string(rolesJSON)); err != nil {
		return err
	}
	return nil
}

// ============================================================================
// AddMembership - Idempotent upsert of a user's membership in a tenant.
//
// First grant inserts an active membership with the given roles; re-adding an
// existing membership replaces its roles and reactivates it (status=active),
// bumping the membership token_version only when the grant actually changes. A
// user_id/tenant_id with no parent row surfaces as model.ErrNotFound rather than a
// raw FK-violation string.
// ============================================================================
func (r *Repository) AddMembership(ctx context.Context, req model.AddMembershipRequest) error {
	if err := r.upsertMembership(ctx, r.rw, req.UserID, req.TenantID, req.Roles); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == foreignKeyViolation {
			return fmt.Errorf("user or tenant not found: %w", model.ErrNotFound)
		}
		return fmt.Errorf("failed to add membership: %w", err)
	}
	return nil
}

// ============================================================================
// RemoveMembership - Revokes a user's membership in a tenant.
//
// Soft-revoke: the row is retained with status=suspended and its token_version is
// bumped (only on the active->suspended transition), so every access token already
// minted for this workspace is rejected by ValidateJWT (version mismatch and/or the
// non-active status) while the row stays available for an idempotent re-grant via
// AddMembership. Returns model.ErrNotFound when no such membership exists. The
// updated_at column is maintained by the BEFORE UPDATE trigger.
// ============================================================================
func (r *Repository) RemoveMembership(ctx context.Context, userID, tenantID string) error {
	query := `
		UPDATE {{schema}}.memberships
		SET status = 'suspended',
		    token_version = token_version + CASE WHEN status = 'active' THEN 1 ELSE 0 END
		WHERE user_id = $1 AND tenant_id = $2
	`
	result, err := r.rw.ExecContext(ctx, r.q(query), userID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to remove membership: %w", err)
	}
	return requireRowsAffected(result, fmt.Errorf("membership not found: %w", model.ErrNotFound))
}

// ============================================================================
// UpdateMembershipRoles - Replaces a membership's roles in a tenant.
//
// Bumps the membership token_version so any already-issued access token for this
// workspace (which embeds the roles in its claims) is rejected by ValidateJWT; the
// next refresh re-reads the new roles. The bump is unconditional — an explicit role
// update is taken at face value even when the new set equals the old. Returns
// model.ErrNotFound when no such membership exists. A nil roles slice is stored as
// an empty JSON array. The updated_at column is maintained by the trigger.
// ============================================================================
func (r *Repository) UpdateMembershipRoles(ctx context.Context, userID, tenantID string, roles []string) error {
	if roles == nil {
		roles = []string{}
	}
	rolesJSON, err := json.Marshal(roles)
	if err != nil {
		return fmt.Errorf("failed to marshal roles: %w", err)
	}

	query := `
		UPDATE {{schema}}.memberships
		SET roles = $3::jsonb,
		    token_version = token_version + 1
		WHERE user_id = $1 AND tenant_id = $2
	`
	result, err := r.rw.ExecContext(ctx, r.q(query), userID, tenantID, string(rolesJSON))
	if err != nil {
		return fmt.Errorf("failed to update membership roles: %w", err)
	}
	return requireRowsAffected(result, fmt.Errorf("membership not found: %w", model.ErrNotFound))
}

// getMembership is the (user_id, tenant_id) lookup against the supplied handle (rw
// or ro), shared by GetMembership (replica) and GetMembershipFromPrimary (primary).
func (r *Repository) getMembership(ctx context.Context, db rowQuerier, userID, tenantID string) (*model.Membership, error) {
	query := `SELECT ` + membershipColumns + ` FROM {{schema}}.memberships WHERE user_id = $1 AND tenant_id = $2`

	m, err := scanMembership(db.QueryRowContext(ctx, r.q(query), userID, tenantID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("membership not found: %w", model.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get membership: %w", err)
	}
	return m, nil
}

// ============================================================================
// GetMembership - Retrieves one (user, tenant) membership. Reads from the read
// replica (ro) — use GetMembershipFromPrimary for the JWT-validation gate.
// ============================================================================
func (r *Repository) GetMembership(ctx context.Context, userID, tenantID string) (*model.Membership, error) {
	return r.getMembership(ctx, r.ro, userID, tenantID)
}

// ============================================================================
// GetMembershipFromPrimary - Like GetMembership but reads from the PRIMARY (rw).
//
// It backs AuthService.ValidateJWT, where the membership's token_version and status
// must reflect the latest writes immediately: UpdateMembershipRoles / RemoveMembership
// bump token_version (and suspend) on rw, and a lagging replica would otherwise let a
// just-revoked or role-changed workspace token keep passing validation for the
// replication-lag window — a fail-open gap. This mirrors GetByIDFromPrimary for the
// identity-level checks.
// ============================================================================
func (r *Repository) GetMembershipFromPrimary(ctx context.Context, userID, tenantID string) (*model.Membership, error) {
	return r.getMembership(ctx, r.rw, userID, tenantID)
}

// ============================================================================
// ListMembershipsByUser - Lists a user's memberships (their workspaces), newest
// first. Includes suspended memberships; the caller filters on Status if it wants
// only active workspaces.
// ============================================================================
func (r *Repository) ListMembershipsByUser(ctx context.Context, userID string) ([]*model.Membership, error) {
	query := `SELECT ` + membershipColumns + `
		FROM {{schema}}.memberships
		WHERE user_id = $1
		ORDER BY created_at DESC`

	rows, err := r.ro.QueryContext(ctx, r.q(query), userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships by user: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var memberships []*model.Membership
	for rows.Next() {
		m, err := scanMembership(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan membership row: %w", err)
		}
		memberships = append(memberships, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating membership rows: %w", err)
	}
	return memberships, nil
}

// ============================================================================
// ListMembershipsByTenant - Lists a tenant's memberships (its members), newest
// first (served by idx_memberships_tenant). Includes suspended memberships; the
// caller filters on Status if it wants only active members.
// ============================================================================
func (r *Repository) ListMembershipsByTenant(ctx context.Context, tenantID string) ([]*model.Membership, error) {
	query := `SELECT ` + membershipColumns + `
		FROM {{schema}}.memberships
		WHERE tenant_id = $1
		ORDER BY created_at DESC`

	rows, err := r.ro.QueryContext(ctx, r.q(query), tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships by tenant: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var memberships []*model.Membership
	for rows.Next() {
		m, err := scanMembership(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan membership row: %w", err)
		}
		memberships = append(memberships, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating membership rows: %w", err)
	}
	return memberships, nil
}

// ============================================================================
// CountMembershipsByTenant - Returns the number of memberships in a tenant
// (status-agnostic: active and suspended both count). Replaces the old
// CountUsersByTenant now that "a tenant's users" is the membership graph.
// ============================================================================
func (r *Repository) CountMembershipsByTenant(ctx context.Context, tenantID string) (int, error) {
	query := `SELECT COUNT(*) FROM {{schema}}.memberships WHERE tenant_id = $1`

	var count int
	if err := r.ro.QueryRowContext(ctx, r.q(query), tenantID).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count memberships: %w", err)
	}
	return count, nil
}
