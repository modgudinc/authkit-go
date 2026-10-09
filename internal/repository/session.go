// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/model"
)

const sessionColumns = "id, user_id, namespace, installation_id, sign_in_method, token_version, created_at, last_used_at, expires_at, absolute_expires_at, revoked_at, revocation_reason"

type sessionScanner interface{ Scan(...any) error }

func scanSession(row sessionScanner) (*model.Session, error) {
	var s model.Session
	err := row.Scan(&s.ID, &s.UserID, &s.Namespace, &s.InstallationID, &s.SignInMethod, &s.TokenVersion,
		&s.CreatedAt, &s.LastUsedAt, &s.ExpiresAt, &s.AbsoluteExpiresAt, &s.RevokedAt, &s.RevocationReason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *Repository) GetSession(ctx context.Context, namespace, userID, sessionID string) (*model.Session, error) {
	return scanSession(r.rw.QueryRowContext(ctx, r.q("SELECT "+sessionColumns+
		" FROM {{schema}}.sessions WHERE namespace=$1 AND user_id=$2 AND id=$3"),
		namespace, userID, sessionID))
}

// SessionForRefresh deliberately includes consumed tokens: their family still
// identifies a session, and the caller must distinguish session revocation from
// active-session token reuse. A missing session must never downgrade to legacy.
func (r *Repository) SessionForRefresh(ctx context.Context, namespace, hash string) (*model.Session, error) {
	var userID, familyID string
	err := r.rw.QueryRowContext(ctx, r.q("SELECT user_id, family_id FROM {{schema}}.refresh_tokens WHERE token_hash=$1"), hash).Scan(&userID, &familyID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, model.ErrInvalidRefreshToken
	}
	if err != nil {
		return nil, err
	}
	s, err := r.GetSession(ctx, namespace, userID, familyID)
	if errors.Is(err, model.ErrNotFound) {
		return nil, model.ErrSessionRevoked
	}
	return s, err
}

func (r *Repository) ListSessions(ctx context.Context, namespace, userID string, limit, offset int) ([]model.Session, error) {
	rows, err := r.rw.QueryContext(ctx, r.q("SELECT "+sessionColumns+
		" FROM {{schema}}.sessions WHERE namespace=$1 AND user_id=$2 ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4"),
		namespace, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	result := []model.Session{}
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *s)
	}
	return result, rows.Err()
}

// All bound-session mutations lock user -> session -> refresh rows. Identity
// status changes already lock the user first; this avoids inversions with them.
func (r *Repository) lockSessionUser(ctx context.Context, tx *sql.Tx, userID string) (*model.User, error) {
	return scanUser(tx.QueryRowContext(ctx, r.q("SELECT "+userColumns+" FROM {{schema}}.users WHERE id=$1 FOR UPDATE"), userID))
}

func sessionAccountActive(u *model.User) bool {
	return u.IsEnabled && (!u.IsLocked || (u.LockedUntil != nil && !time.Now().Before(*u.LockedUntil)))
}

func sessionActive(s *model.Session, u *model.User, now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.ExpiresAt) && now.Before(s.AbsoluteExpiresAt) &&
		s.TokenVersion == u.TokenVersion && sessionAccountActive(u)
}

// CreateBoundSession atomically opens the session and its first refresh token.
// expectedUser is the snapshot the caller authenticated or verified: if the account
// was disabled, locked or had its credentials changed since, nothing is written.
func (r *Repository) CreateBoundSession(ctx context.Context, expectedUser *model.User, s *model.Session, token CreateRefreshTokenRequest) error {
	tx, err := r.rw.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	u, err := r.lockSessionUser(ctx, tx, expectedUser.ID)
	if err != nil {
		return err
	}
	if !sessionAccountActive(u) || u.TokenVersion != expectedUser.TokenVersion || u.PasswordHash != expectedUser.PasswordHash {
		return model.ErrInvalidCredentials
	}
	_, err = tx.ExecContext(ctx, r.q(`
		INSERT INTO {{schema}}.sessions
		(id,user_id,namespace,installation_id,sign_in_method,token_version,created_at,last_used_at,expires_at,absolute_expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$7,$8,$9)`),
		s.ID, u.ID, s.Namespace, s.InstallationID, s.SignInMethod, u.TokenVersion, s.CreatedAt, s.ExpiresAt, s.AbsoluteExpiresAt)
	if err != nil {
		return err
	}
	if err := r.insertSessionRefresh(ctx, tx, s, token); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) insertSessionRefresh(ctx context.Context, tx *sql.Tx, s *model.Session, req CreateRefreshTokenRequest) error {
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, r.q(`
		INSERT INTO {{schema}}.refresh_tokens
		(id,user_id,token_hash,family_id,ip_address,user_agent,device_name,last_used_at,expires_at,created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$8)`),
		id.String(), s.UserID, req.TokenHash, s.ID, req.IPAddress, req.UserAgent, req.DeviceName, time.Now(), s.ExpiresAt)
	return err
}

// RotateBoundRefresh checks account, session and workspace inside the same
// transaction as rotation. It returns the authoritative snapshots for minting.
func (r *Repository) RotateBoundRefresh(ctx context.Context, namespace, oldHash, tenantID string, req CreateRefreshTokenRequest) (*model.User, *model.Membership, *model.Session, error) {
	tx, err := r.rw.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var userID, familyID string
	err = tx.QueryRowContext(ctx, r.q("SELECT user_id, family_id FROM {{schema}}.refresh_tokens WHERE token_hash=$1"), oldHash).Scan(&userID, &familyID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil, model.ErrInvalidRefreshToken
	}
	if err != nil {
		return nil, nil, nil, err
	}
	u, err := r.lockSessionUser(ctx, tx, userID)
	if err != nil {
		return nil, nil, nil, err
	}
	s, err := scanSession(tx.QueryRowContext(ctx, r.q("SELECT "+sessionColumns+
		" FROM {{schema}}.sessions WHERE id=$1 AND user_id=$2 AND namespace=$3 FOR UPDATE"), familyID, userID, namespace))
	if errors.Is(err, model.ErrNotFound) {
		return nil, nil, nil, model.ErrSessionRevoked
	}
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	if !sessionActive(s, u, now) {
		return nil, nil, nil, model.ErrSessionRevoked
	}
	var consumed *time.Time
	var expiry time.Time
	err = tx.QueryRowContext(ctx, r.q("SELECT revoked_at, expires_at FROM {{schema}}.refresh_tokens WHERE token_hash=$1 FOR UPDATE"), oldHash).Scan(&consumed, &expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil, model.ErrInvalidRefreshToken
	}
	if err != nil {
		return nil, nil, nil, err
	}
	if consumed != nil {
		if err := r.revokeSessionTx(ctx, tx, s.ID, "refresh_reuse"); err != nil {
			return nil, nil, nil, err
		}
		// Preserve the existing identity-wide access-token invalidation response.
		if _, err := tx.ExecContext(ctx, r.q("UPDATE {{schema}}.users SET token_version=token_version+1, updated_at=$1 WHERE id=$2"), now, userID); err != nil {
			return nil, nil, nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, nil, nil, err
		}
		return nil, nil, nil, &model.RefreshTokenReuseError{UserID: userID, FamilyID: familyID}
	}
	if !now.Before(expiry) {
		return nil, nil, nil, model.ErrInvalidRefreshToken
	}
	// No token is consumed for a workspace the user cannot access.
	m, err := scanMembership(tx.QueryRowContext(ctx, r.q("SELECT "+membershipColumns+" FROM {{schema}}.memberships WHERE user_id=$1 AND tenant_id=$2"), userID, tenantID))
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, model.ErrNotFound) {
		return nil, nil, nil, model.ErrNoActiveMembership
	}
	if err != nil {
		return nil, nil, nil, err
	}
	if !m.IsActive() {
		return nil, nil, nil, model.ErrNoActiveMembership
	}
	s.ExpiresAt = req.ExpiresAt
	if s.AbsoluteExpiresAt.Before(s.ExpiresAt) {
		s.ExpiresAt = s.AbsoluteExpiresAt
	}
	s.LastUsedAt = now
	if _, err := tx.ExecContext(ctx, r.q("UPDATE {{schema}}.refresh_tokens SET revoked_at=$1 WHERE token_hash=$2"), now, oldHash); err != nil {
		return nil, nil, nil, err
	}
	if _, err := tx.ExecContext(ctx, r.q("UPDATE {{schema}}.sessions SET expires_at=$1,last_used_at=$2 WHERE id=$3"), s.ExpiresAt, now, s.ID); err != nil {
		return nil, nil, nil, err
	}
	if err := r.insertSessionRefresh(ctx, tx, s, req); err != nil {
		return nil, nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, nil, err
	}
	return u, m, s, nil
}

func (r *Repository) revokeSessionTx(ctx context.Context, tx *sql.Tx, sessionID, reason string) error {
	now := time.Now()
	if _, err := tx.ExecContext(ctx, r.q("UPDATE {{schema}}.sessions SET revoked_at=$1,revocation_reason=$2 WHERE id=$3 AND revoked_at IS NULL"), now, reason, sessionID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, r.q("UPDATE {{schema}}.refresh_tokens SET revoked_at=$1 WHERE family_id=$2 AND revoked_at IS NULL"), now, sessionID)
	return err
}

// RevokeSessions scopes every lookup by application and owner. sessionID selects
// one session; installationID selects all logins for that installation.
func (r *Repository) RevokeSessions(ctx context.Context, namespace, userID, sessionID, installationID, reason string) error {
	tx, err := r.rw.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := r.lockSessionUser(ctx, tx, userID); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, r.q(`
		SELECT id FROM {{schema}}.sessions WHERE namespace=$1 AND user_id=$2
		AND (($3<>'' AND id=$3) OR ($4<>'' AND installation_id=$4))
		ORDER BY id FOR UPDATE`), namespace, userID, sessionID, installationID)
	if err != nil {
		return err
	}
	var ids []string
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	readErr := rows.Err()
	if readErr != nil {
		return readErr
	}
	if len(ids) == 0 && sessionID != "" {
		return model.ErrNotFound
	}
	for _, id := range ids {
		if err := r.revokeSessionTx(ctx, tx, id, reason); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *Repository) CleanupSessions(ctx context.Context, namespace string) (int64, error) {
	result, err := r.rw.ExecContext(ctx, r.q("DELETE FROM {{schema}}.sessions WHERE namespace=$1 AND expires_at <= $2"), namespace, time.Now())
	if err != nil {
		return 0, fmt.Errorf("cleanup sessions: %w", err)
	}
	return result.RowsAffected()
}

// RevokeUserSessionsAndTokens backs explicit identity-wide credential actions
// when session support is enabled. All namespaces are affected deliberately.
func (r *Repository) RevokeUserSessionsAndTokens(ctx context.Context, userID string) error {
	tx, err := r.rw.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := r.lockSessionUser(ctx, tx, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, r.q("UPDATE {{schema}}.sessions SET revoked_at=$1,revocation_reason='account_action' WHERE user_id=$2 AND revoked_at IS NULL"), time.Now(), userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, r.q("DELETE FROM {{schema}}.refresh_tokens WHERE user_id=$1"), userID); err != nil {
		return err
	}
	return tx.Commit()
}
