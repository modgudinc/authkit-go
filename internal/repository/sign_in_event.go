// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/modgudinc/authkit-go/model"
)

// InsertSignInEvent stores one row of a user's sign-in history (migration 000007).
// The caller has already cleaned the event's free-text fields: IPAddress is a
// parsed address or "", and no field holds a NUL byte or invalid UTF-8. Empty
// IPAddress, UserAgent and DeviceName are stored as NULL.
func (r *Repository) InsertSignInEvent(ctx context.Context, e *model.SignInEvent) error {
	const insert = `
		INSERT INTO {{schema}}.sign_in_events (
			id, user_id, occurred_at, method, succeeded, failure_reason, namespace,
			tenant_id, session_id, installation_id, ip_address, user_agent, device_name
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`
	if _, err := r.writer(ctx).ExecContext(ctx, r.q(insert),
		e.ID, e.UserID, e.OccurredAt, e.Method, e.Succeeded, e.FailureReason, e.Namespace,
		e.TenantID, e.SessionID, e.InstallationID,
		nullIfEmpty(e.IPAddress), nullIfEmpty(e.UserAgent), nullIfEmpty(e.DeviceName),
	); err != nil {
		return fmt.Errorf("failed to record sign-in: %w", err)
	}
	return nil
}

// ListSignInEvents returns a page of a user's sign-in history, newest first. Reads
// from the replica (ro): the history is a report, not a security gate.
func (r *Repository) ListSignInEvents(ctx context.Context, userID string, limit, offset int) ([]*model.SignInEvent, error) {
	const query = `
		SELECT id, user_id, occurred_at, method, succeeded, failure_reason, namespace,
			tenant_id, session_id, installation_id, host(ip_address), user_agent, device_name
		FROM {{schema}}.sign_in_events
		WHERE user_id = $1
		ORDER BY occurred_at DESC, id DESC
		LIMIT $2 OFFSET $3`
	rows, err := r.reader(ctx).QueryContext(ctx, r.q(query), userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list sign-in history: %w", err)
	}
	defer func() { _ = rows.Close() }()

	events := []*model.SignInEvent{}
	for rows.Next() {
		var (
			e                   model.SignInEvent
			ip, agent, nameText sql.NullString
		)
		if err := rows.Scan(&e.ID, &e.UserID, &e.OccurredAt, &e.Method, &e.Succeeded, &e.FailureReason, &e.Namespace,
			&e.TenantID, &e.SessionID, &e.InstallationID, &ip, &agent, &nameText); err != nil {
			return nil, fmt.Errorf("failed to scan sign-in history row: %w", err)
		}
		e.IPAddress, e.UserAgent, e.DeviceName = ip.String, agent.String, nameText.String
		events = append(events, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating sign-in history rows: %w", err)
	}
	return events, nil
}

// CleanupSignInEvents deletes sign-in history recorded before cutoff and returns
// the number of rows removed.
func (r *Repository) CleanupSignInEvents(ctx context.Context, cutoff time.Time) (int64, error) {
	result, err := r.writer(ctx).ExecContext(ctx, r.q(`DELETE FROM {{schema}}.sign_in_events WHERE occurred_at < $1`), cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old sign-in history: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}
	return n, nil
}

// nullIfEmpty stores "" as SQL NULL.
func nullIfEmpty(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}
