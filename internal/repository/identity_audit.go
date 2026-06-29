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

	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/model"
)

// ============================================================================
// User status-change audit.
//
// The schema has no DB trigger; the repository writes user_status_changes rows in
// Go, in the same transaction as the status update, so the audit-row id is a
// Go-minted UUIDv7 like every other id. A row is recorded only on an actual
// is_enabled or is_locked transition, with the status_type, changed_by_type, and
// metadata described below. changed_by is left NULL.
//
// The status-changing user mutators (Enable/Disable/Lock/Unlock/Delete ByTenant and
// the automatic RegisterFailedLogin lockout) live in identity.go and drive this
// machinery via withUserStatusAudit / readUserStatusForUpdate / recordStatusChange.
// ============================================================================

// statusChangeActor identifies who initiated a user status change; it is written
// as the changed_by_type of the audit row. Provenance is passed in explicitly by
// the caller rather than inferred from failed_login_count: only the automatic
// failed-login lockout (RegisterFailedLogin) is the system, and every other
// status mutation is an admin action.
type statusChangeActor string

const (
	actorAdmin  statusChangeActor = "admin"
	actorSystem statusChangeActor = "system"
)

// userStatusSnapshot captures the user fields needed to detect an enable/disable
// or lock/unlock transition and build the audit metadata.
type userStatusSnapshot struct {
	IsEnabled        bool
	IsLocked         bool
	LockedUntil      *time.Time
	FailedLoginCount int
	LastFailedLogin  *time.Time
	DisabledAt       *time.Time
}

// readUserStatusForUpdate locks the user row and returns its current status
// snapshot, or model.ErrNotFound if no matching (id[, tenant]) row exists.
func (r *Repository) readUserStatusForUpdate(ctx context.Context, tx *sql.Tx, userID string, tenantID *string) (userStatusSnapshot, error) {
	var s userStatusSnapshot
	var (
		query string
		args  []any
	)
	if tenantID != nil {
		query = `
			SELECT is_enabled, is_locked, locked_until, failed_login_count, last_failed_login, disabled_at
			FROM {{schema}}.users WHERE id = $1 AND tenant_id = $2 FOR UPDATE`
		args = []any{userID, *tenantID}
	} else {
		query = `
			SELECT is_enabled, is_locked, locked_until, failed_login_count, last_failed_login, disabled_at
			FROM {{schema}}.users WHERE id = $1 FOR UPDATE`
		args = []any{userID}
	}
	err := tx.QueryRowContext(ctx, r.q(query), args...).Scan(
		&s.IsEnabled, &s.IsLocked, &s.LockedUntil, &s.FailedLoginCount, &s.LastFailedLogin, &s.DisabledAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return s, fmt.Errorf("user not found: %w", model.ErrNotFound)
		}
		return s, fmt.Errorf("failed to read user status: %w", err)
	}
	return s, nil
}

// recordStatusChange inserts a user_status_changes row for any is_enabled /
// is_locked transition between old and current, attributing it to actor. actor is
// the operation's provenance (admin for explicit admin mutations, system for the
// automatic failed-login lockout), not something inferred from the row state.
func (r *Repository) recordStatusChange(ctx context.Context, tx *sql.Tx, userID string, old, current userStatusSnapshot, actor statusChangeActor) error {
	if old.IsEnabled != current.IsEnabled {
		statusType := "disable"
		if current.IsEnabled {
			statusType = "enable"
		}
		if err := r.insertUserStatusChange(ctx, tx, userID, statusType, string(actor), map[string]any{
			"previous_state": old.IsEnabled,
			"new_state":      current.IsEnabled,
			"disabled_at":    current.DisabledAt,
		}); err != nil {
			return err
		}
	}
	if old.IsLocked != current.IsLocked {
		statusType := "unlock"
		if current.IsLocked {
			statusType = "lock"
		}
		if err := r.insertUserStatusChange(ctx, tx, userID, statusType, string(actor), map[string]any{
			"previous_state":    old.IsLocked,
			"new_state":         current.IsLocked,
			"locked_until":      current.LockedUntil,
			"failed_attempts":   current.FailedLoginCount,
			"last_failed_login": current.LastFailedLogin,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) insertUserStatusChange(ctx context.Context, tx *sql.Tx, userID string, statusType, changedByType string, metadata map[string]any) error {
	gen, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("could not generate id for status change: %w", err)
	}
	id := gen.String()
	metaJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal status change metadata: %w", err)
	}
	const insert = `
		INSERT INTO {{schema}}.user_status_changes (id, user_id, status_type, changed_by_type, metadata, changed_at)
		VALUES ($1, $2, $3, $4, $5, NOW())`
	if _, err := tx.ExecContext(ctx, r.q(insert), id, userID, statusType, changedByType, metaJSON); err != nil {
		return fmt.Errorf("failed to record status change: %w", err)
	}
	return nil
}

// ListUserStatusChanges returns a user's account status-change audit trail, newest
// first. It is tenant-scoped via a JOIN to users, so a caller-supplied id from
// another tenant matches no rows (and a hard-deleted user has none). Reads from the
// replica (ro): the audit trail is an admin/report read, not a security gate.
func (r *Repository) ListUserStatusChanges(ctx context.Context, userID string, tenantID string) ([]*model.UserStatusChange, error) {
	query := `
		SELECT sc.id, sc.user_id, sc.status_type, sc.changed_by, sc.changed_by_type, sc.changed_at, sc.reason, sc.metadata
		FROM {{schema}}.user_status_changes sc
		JOIN {{schema}}.users u ON u.id = sc.user_id
		WHERE sc.user_id = $1 AND u.tenant_id = $2
		ORDER BY sc.changed_at DESC
	`
	rows, err := r.ro.QueryContext(ctx, r.q(query), userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list user status changes: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var changes []*model.UserStatusChange
	for rows.Next() {
		var (
			c         model.UserStatusChange
			changedBy sql.NullString
			reason    *string
			metaJSON  []byte
		)
		if err := rows.Scan(&c.ID, &c.UserID, &c.StatusType, &changedBy, &c.ChangedByType, &c.ChangedAt, &reason, &metaJSON); err != nil {
			return nil, fmt.Errorf("failed to scan user status change row: %w", err)
		}
		if changedBy.Valid {
			id := changedBy.String
			c.ChangedBy = &id
		}
		c.Reason = reason
		if len(metaJSON) > 0 {
			if err := json.Unmarshal(metaJSON, &c.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal status change metadata: %w", err)
			}
		}
		changes = append(changes, &c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user status change rows: %w", err)
	}
	return changes, nil
}

// CleanupStatusChanges deletes status-change audit rows recorded before cutoff and
// returns the number removed. The user_status_changes table has no expiry column
// and grows for the life of the deployment, so callers should run this periodically
// (like the other CleanupExpired jobs) per their retention policy.
func (r *Repository) CleanupStatusChanges(ctx context.Context, cutoff time.Time) (int64, error) {
	result, err := r.rw.ExecContext(ctx, r.q(`DELETE FROM {{schema}}.user_status_changes WHERE changed_at < $1`), cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old status changes: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}
	return n, nil
}

// withUserStatusAudit runs a status-changing user UPDATE and its audit row(s) in
// one transaction: it locks the target row (model.ErrNotFound if absent / wrong
// tenant), calls apply (which performs the UPDATE and returns the resulting
// snapshot), records any transition attributed to actor, and commits. All of its
// callers are explicit admin mutations, so they pass actorAdmin.
func (r *Repository) withUserStatusAudit(ctx context.Context, userID string, tenantID *string, actor statusChangeActor, apply func(ctx context.Context, tx *sql.Tx, old userStatusSnapshot) (userStatusSnapshot, error)) error {
	tx, err := r.rw.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin user status update: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	old, err := r.readUserStatusForUpdate(ctx, tx, userID, tenantID)
	if err != nil {
		return err
	}
	current, err := apply(ctx, tx, old)
	if err != nil {
		return err
	}
	if err := r.recordStatusChange(ctx, tx, userID, old, current, actor); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit user status update: %w", err)
	}
	committed = true
	return nil
}
