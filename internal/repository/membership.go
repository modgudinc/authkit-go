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

// execer is the write surface shared by the rw *sql.DB handle and a transaction, so the
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
	if err := r.upsertMembership(ctx, r.writer(ctx), req.UserID, req.TenantID, req.Roles); err != nil {
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
	result, err := r.writer(ctx).ExecContext(ctx, r.q(query), userID, tenantID)
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
	result, err := r.writer(ctx).ExecContext(ctx, r.q(query), userID, tenantID, string(rolesJSON))
	if err != nil {
		return fmt.Errorf("failed to update membership roles: %w", err)
	}
	return requireRowsAffected(result, fmt.Errorf("membership not found: %w", model.ErrNotFound))
}

// ============================================================================
// RemoveMembershipGuarded - RemoveMembership with a last-holder safety guard.
//
// Soft-revokes the membership exactly like RemoveMembership, but refuses to remove
// the tenant's last ACTIVE member holding requireRole (e.g. the workspace's last
// Admin): the revoke is rolled back and model.ErrLastRoleHolder is returned. The
// revoke and the "does an active holder of requireRole still remain?" check run in
// one transaction serialized per tenant by a transaction-scoped advisory lock, so
// two concurrent removals of the last two holders — even from different processes /
// instances — cannot both succeed, and a tenant can never be left with zero active
// holders of the role. Returns model.ErrNotFound when no such membership exists. An
// empty requireRole disables the guard (behaves like RemoveMembership).
// ============================================================================
func (r *Repository) RemoveMembershipGuarded(ctx context.Context, userID, tenantID, requireRole string) error {
	return r.withGuardedTx(ctx, tenantID, requireRole, func(tx dbtx) error {
		query := `
			UPDATE {{schema}}.memberships
			SET status = 'suspended',
			    token_version = token_version + CASE WHEN status = 'active' THEN 1 ELSE 0 END
			WHERE user_id = $1 AND tenant_id = $2
		`
		result, err := tx.ExecContext(ctx, r.q(query), userID, tenantID)
		if err != nil {
			return fmt.Errorf("failed to remove membership: %w", err)
		}
		return requireRowsAffected(result, fmt.Errorf("membership not found: %w", model.ErrNotFound))
	})
}

// ============================================================================
// UpdateMembershipRolesGuarded - UpdateMembershipRoles with the same last-holder
// guard as RemoveMembershipGuarded.
//
// Replaces the membership's roles (bumping the membership token_version) but refuses
// to leave the tenant with no active member holding requireRole — e.g. demoting the
// workspace's last Admin — rolling back and returning model.ErrLastRoleHolder. The
// guard is enforced on the POST-update state (so promoting the target INTO requireRole
// is always allowed) inside a per-tenant serialized transaction. Returns
// model.ErrNotFound when no such membership exists; a nil roles slice is stored as an
// empty JSON array; an empty requireRole disables the guard.
// ============================================================================
func (r *Repository) UpdateMembershipRolesGuarded(ctx context.Context, userID, tenantID string, roles []string, requireRole string) error {
	if roles == nil {
		roles = []string{}
	}
	rolesJSON, err := json.Marshal(roles)
	if err != nil {
		return fmt.Errorf("failed to marshal roles: %w", err)
	}
	return r.withGuardedTx(ctx, tenantID, requireRole, func(tx dbtx) error {
		query := `
			UPDATE {{schema}}.memberships
			SET roles = $3::jsonb,
			    token_version = token_version + 1
			WHERE user_id = $1 AND tenant_id = $2
		`
		result, err := tx.ExecContext(ctx, r.q(query), userID, tenantID, string(rolesJSON))
		if err != nil {
			return fmt.Errorf("failed to update membership roles: %w", err)
		}
		return requireRowsAffected(result, fmt.Errorf("membership not found: %w", model.ErrNotFound))
	})
}

// withGuardedTx runs mutate inside a transaction that (1) takes a per-tenant advisory
// lock so concurrent guarded mutations for the same tenant serialize across every
// caller and process, and (2) after mutate succeeds, asserts that at least one ACTIVE
// member still holds requireRole — rolling back with model.ErrLastRoleHolder if not.
// Because the invariant is checked on the post-mutation state while holding the tenant
// lock, the last active holder of the role can never be removed or demoted out from
// under a concurrent check. An empty requireRole skips the invariant (no guard). A
// mutate error (e.g. model.ErrNotFound) is returned as-is and rolls the tx back.
func (r *Repository) withGuardedTx(ctx context.Context, tenantID, requireRole string, mutate func(tx dbtx) error) error {
	tx, err := r.begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin guarded membership tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Serialize guarded mutations for this tenant across all callers/instances. The
	// lock key is derived from the tenant id; a hash collision between two tenants only
	// makes them briefly share the lock (a negligible contention cost, never a
	// correctness issue). It is transaction-scoped: auto-released on commit or rollback.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, tenantID); err != nil {
		return fmt.Errorf("failed to acquire tenant guard lock: %w", err)
	}

	if err := mutate(tx); err != nil {
		return err
	}

	if requireRole != "" {
		remains, err := r.hasActiveRoleHolder(ctx, tx, tenantID, requireRole)
		if err != nil {
			return err
		}
		if !remains {
			return fmt.Errorf("would leave tenant %q with no active %q: %w", tenantID, requireRole, model.ErrLastRoleHolder)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit guarded membership tx: %w", err)
	}
	committed = true
	return nil
}

// hasActiveRoleHolder reports whether the tenant has at least one ACTIVE member whose
// roles include role and whose account is enabled, so a disabled (or deleted) user
// never counts as the holder that keeps the tenant manageable. A locked account
// still counts: a lock is usually the failed-login lockout and lifts by itself. It
// runs on the supplied querier — a *sql.Tx during a guarded mutation, so it observes
// that transaction's own uncommitted change — and tests role membership against the
// JSONB roles array with the @> containment operator. UserService.Disable is an
// account-level action and is not guarded: disabling a tenant's last enabled holder
// is allowed, and the guard then refuses to remove or demote anyone else holding the
// role.
func (r *Repository) hasActiveRoleHolder(ctx context.Context, q rowQuerier, tenantID, role string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM {{schema}}.memberships m
			JOIN {{schema}}.users u ON u.id = m.user_id
			WHERE m.tenant_id = $1
			  AND m.status = 'active'
			  AND m.roles @> jsonb_build_array($2::text)
			  AND u.is_enabled
		)
	`
	var exists bool
	if err := q.QueryRowContext(ctx, r.q(query), tenantID, role).Scan(&exists); err != nil {
		return false, fmt.Errorf("failed to check active role holders: %w", err)
	}
	return exists, nil
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
	return r.getMembership(ctx, r.reader(ctx), userID, tenantID)
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
	return r.getMembership(ctx, r.writer(ctx), userID, tenantID)
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

	rows, err := r.reader(ctx).QueryContext(ctx, r.q(query), userID)
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

	rows, err := r.reader(ctx).QueryContext(ctx, r.q(query), tenantID)
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
	if err := r.reader(ctx).QueryRowContext(ctx, r.q(query), tenantID).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count memberships: %w", err)
	}
	return count, nil
}
