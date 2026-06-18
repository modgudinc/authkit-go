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
func (r *Repository) readUserStatusForUpdate(ctx context.Context, tx *sql.Tx, userID uuid.UUID, tenantID *string) (userStatusSnapshot, error) {
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
func (r *Repository) recordStatusChange(ctx context.Context, tx *sql.Tx, userID uuid.UUID, old, current userStatusSnapshot, actor statusChangeActor) error {
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

func (r *Repository) insertUserStatusChange(ctx context.Context, tx *sql.Tx, userID uuid.UUID, statusType, changedByType string, metadata map[string]any) error {
	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("could not generate id for status change: %w", err)
	}
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

// withUserStatusAudit runs a status-changing user UPDATE and its audit row(s) in
// one transaction: it locks the target row (model.ErrNotFound if absent / wrong
// tenant), calls apply (which performs the UPDATE and returns the resulting
// snapshot), records any transition attributed to actor, and commits. All of its
// callers are explicit admin mutations, so they pass actorAdmin.
func (r *Repository) withUserStatusAudit(ctx context.Context, userID uuid.UUID, tenantID *string, actor statusChangeActor, apply func(ctx context.Context, tx *sql.Tx, old userStatusSnapshot) (userStatusSnapshot, error)) error {
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
