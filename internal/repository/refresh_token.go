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

// Refresh Token Repository Methods:
//
// Token Management:
// - CreateRefreshToken  - Stores a new refresh token with session metadata
// - GetByTokenHash      - Retrieves a refresh token by its SHA256 hash
// - GetByUserID         - Lists all refresh tokens for a specific user
// - UpdateLastUsed      - Updates the last_used_at timestamp (async operation)
//
// Token Revocation:
// - DeleteByTokenHash   - Revokes a specific refresh token
// - DeleteByUserID      - Revokes all refresh tokens for a user (logout all sessions)
// - DeleteExpired       - Cleanup expired refresh tokens (maintenance job)

// ============================================================================
// CreateRefreshToken - Stores a new refresh token with session metadata
// ============================================================================
func (r *Repository) CreateRefreshToken(ctx context.Context, req model.CreateRefreshTokenRequest) (uuid.UUID, error) {
	tokenID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("could not generate ID for refresh token: %w", err)
	}

	// A fresh login starts a new token family; a rotation passes the existing one.
	familyID := req.FamilyID
	if familyID == uuid.Nil {
		familyID, err = uuid.NewV7()
		if err != nil {
			return uuid.Nil, fmt.Errorf("could not generate family ID for refresh token: %w", err)
		}
	}

	query := `
		INSERT INTO {{schema}}.refresh_tokens (
			id, user_id, token_hash, family_id, ip_address, user_agent, device_name,
			last_used_at, expires_at, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	now := time.Now()
	_, err = r.rw.ExecContext(ctx, r.q(query),
		tokenID,
		req.UserID,
		req.TokenHash,
		familyID,
		req.IPAddress,
		req.UserAgent,
		req.DeviceName,
		now, // last_used_at initialized to creation time
		req.ExpiresAt,
		now,
	)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	return tokenID, nil
}

// ============================================================================
// RotateRefreshToken - Atomically consumes one refresh token and stores a new one
// ============================================================================
func (r *Repository) RotateRefreshToken(ctx context.Context, oldTokenHash string, req model.CreateRefreshTokenRequest) (*model.User, uuid.UUID, error) {
	tx, err := r.rw.BeginTx(ctx, nil)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("failed to begin refresh token rotation: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Look up the presented token (locked) regardless of its revoked/expired
	// state so we can distinguish "never existed" from "already consumed" (reuse).
	lookupQuery := `
		SELECT user_id, family_id, revoked_at, expires_at
		FROM {{schema}}.refresh_tokens
		WHERE token_hash = $1
		FOR UPDATE
	`

	var userID, familyID uuid.UUID
	var revokedAt *time.Time
	var expiresAt time.Time
	if err := tx.QueryRowContext(ctx, r.q(lookupQuery), oldTokenHash).Scan(&userID, &familyID, &revokedAt, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, uuid.Nil, fmt.Errorf("refresh token not found: %w", model.ErrInvalidRefreshToken)
		}
		return nil, uuid.Nil, fmt.Errorf("failed to look up refresh token: %w", err)
	}

	// Reuse/theft: an already-consumed token is being presented again. Revoke the
	// entire family (every still-active token descended from the same login) so
	// neither the legitimate holder nor an attacker can keep refreshing.
	if revokedAt != nil {
		if _, err := tx.ExecContext(ctx, r.q(`
			UPDATE {{schema}}.refresh_tokens
			SET revoked_at = $1
			WHERE family_id = $2 AND revoked_at IS NULL
		`), time.Now(), familyID); err != nil {
			return nil, uuid.Nil, fmt.Errorf("failed to revoke reused token family: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return nil, uuid.Nil, fmt.Errorf("failed to commit token family revocation: %w", err)
		}
		committed = true
		return nil, uuid.Nil, fmt.Errorf("refresh token reuse detected: %w", model.ErrRefreshTokenReuse)
	}

	now := time.Now()

	// Expired: consume it and reject.
	if now.After(expiresAt) {
		if _, err := tx.ExecContext(ctx, r.q(`UPDATE {{schema}}.refresh_tokens SET revoked_at = $1 WHERE token_hash = $2`), now, oldTokenHash); err != nil {
			return nil, uuid.Nil, fmt.Errorf("failed to revoke expired refresh token: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return nil, uuid.Nil, fmt.Errorf("failed to commit: %w", err)
		}
		committed = true
		return nil, uuid.Nil, fmt.Errorf("refresh token expired: %w", model.ErrInvalidRefreshToken)
	}

	// Consume (soft-revoke) the presented token. It is retained, not deleted, so a
	// later replay is detectable until the row is cleaned up after expiry.
	if _, err := tx.ExecContext(ctx, r.q(`UPDATE {{schema}}.refresh_tokens SET revoked_at = $1 WHERE token_hash = $2`), now, oldTokenHash); err != nil {
		return nil, uuid.Nil, fmt.Errorf("failed to consume refresh token: %w", err)
	}

	userQuery := `
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
	if err := tx.QueryRowContext(ctx, r.q(userQuery), userID).Scan(
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
	); err != nil {
		return nil, uuid.Nil, fmt.Errorf("failed to get user for refresh token: %w", err)
	}

	if err := json.Unmarshal(rolesJSON, &user.Roles); err != nil {
		return nil, uuid.Nil, fmt.Errorf("failed to unmarshal roles: %w", err)
	}

	user.DisabledAt = disabledAt
	user.LockedUntil = lockedUntil
	user.LastFailedLoginAt = lastFailedLogin
	user.LastLoginAt = lastLogin

	tokenID, err := uuid.NewV7()
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("could not generate ID for refresh token: %w", err)
	}

	insertQuery := `
		INSERT INTO {{schema}}.refresh_tokens (
			id, user_id, token_hash, family_id, ip_address, user_agent, device_name,
			last_used_at, expires_at, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	if _, err := tx.ExecContext(ctx, r.q(insertQuery),
		tokenID,
		userID,
		req.TokenHash,
		familyID, // replacement stays in the same family as the consumed token
		req.IPAddress,
		req.UserAgent,
		req.DeviceName,
		now,
		req.ExpiresAt,
		now,
	); err != nil {
		return nil, uuid.Nil, fmt.Errorf("failed to create rotated refresh token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, uuid.Nil, fmt.Errorf("failed to commit refresh token rotation: %w", err)
	}
	committed = true

	return &user, tokenID, nil
}

// ============================================================================
// GetByTokenHash - Retrieves a refresh token by its HMAC-SHA256 hash
// Returns ErrInvalidRefreshToken if the token is not found or expired.
//
// Reads from the PRIMARY (rw), not a read replica: this is the credential
// validation path run immediately after a token is issued/rotated, where
// replica lag could spuriously reject a freshly minted token. Do not switch to
// r.ro without accepting that auth-failure risk.
// ============================================================================
func (r *Repository) GetByTokenHash(ctx context.Context, tokenHash string) (*model.RefreshToken, error) {
	query := `
		SELECT
			id, user_id, token_hash, ip_address, user_agent, device_name,
			last_used_at, expires_at, created_at
		FROM {{schema}}.refresh_tokens
		WHERE token_hash = $1
		  AND revoked_at IS NULL
	`

	var token model.RefreshToken
	var ipAddress, userAgent, deviceName *string
	var lastUsedAt *time.Time

	err := r.rw.QueryRowContext(ctx, r.q(query), tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&ipAddress,
		&userAgent,
		&deviceName,
		&lastUsedAt,
		&token.ExpiresAt,
		&token.CreatedAt,
	)
	if err != nil {
		// Translate not-found to the sentinel so callers can branch with
		// errors.Is(err, model.ErrInvalidRefreshToken), matching every sibling
		// Get* method and RotateRefreshToken in this file.
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("refresh token not found: %w", model.ErrInvalidRefreshToken)
		}
		return nil, fmt.Errorf("failed to get refresh token by hash: %w", err)
	}

	// Set nullable fields
	token.IPAddress = ipAddress
	token.UserAgent = userAgent
	token.DeviceName = deviceName
	token.LastUsedAt = lastUsedAt

	// Check if token is expired
	if time.Now().After(token.ExpiresAt) {
		return nil, fmt.Errorf("refresh token has expired: %w", model.ErrInvalidRefreshToken)
	}

	return &token, nil
}

// ============================================================================
// GetByUserID - Lists all refresh tokens for a specific user
// Returns active and expired tokens (caller should filter if needed)
// Ordered by created_at DESC (newest first)
//
// Scoped by user_id only (refresh_tokens has no tenant column). Callers MUST
// tenant-authorize the userID before calling.
// ============================================================================
func (r *Repository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*model.RefreshToken, error) {
	query := `
		SELECT
			id, user_id, token_hash, ip_address, user_agent, device_name,
			last_used_at, expires_at, created_at
		FROM {{schema}}.refresh_tokens
		WHERE user_id = $1
		  AND revoked_at IS NULL
		ORDER BY created_at DESC
	`

	rows, err := r.ro.QueryContext(ctx, r.q(query), userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh tokens by user ID: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var tokens []*model.RefreshToken
	for rows.Next() {
		var token model.RefreshToken
		var ipAddress, userAgent, deviceName *string
		var lastUsedAt *time.Time

		err := rows.Scan(
			&token.ID,
			&token.UserID,
			&token.TokenHash,
			&ipAddress,
			&userAgent,
			&deviceName,
			&lastUsedAt,
			&token.ExpiresAt,
			&token.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan refresh token row: %w", err)
		}

		// Set nullable fields
		token.IPAddress = ipAddress
		token.UserAgent = userAgent
		token.DeviceName = deviceName
		token.LastUsedAt = lastUsedAt

		tokens = append(tokens, &token)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating refresh token rows: %w", err)
	}

	return tokens, nil
}

// ============================================================================
// UpdateLastUsed - Updates the last_used_at timestamp for a refresh token
// This is typically called asynchronously to avoid blocking token validation
// ============================================================================
func (r *Repository) UpdateLastUsed(ctx context.Context, tokenID uuid.UUID) error {
	query := `
		UPDATE {{schema}}.refresh_tokens
		SET last_used_at = $1
		WHERE id = $2
	`

	_, err := r.rw.ExecContext(ctx, r.q(query), time.Now(), tokenID)
	if err != nil {
		return fmt.Errorf("failed to update last used timestamp: %w", err)
	}

	return nil
}

// ============================================================================
// DeleteByTokenHash - Revokes a specific refresh token by its hash
// Used for single session logout
// ============================================================================
func (r *Repository) DeleteByTokenHash(ctx context.Context, tokenHash string) error {
	query := `
		DELETE FROM {{schema}}.refresh_tokens
		WHERE token_hash = $1
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), tokenHash)
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("refresh token not found")
	}

	return nil
}

// ============================================================================
// DeleteByUserID - Revokes all refresh tokens for a user
// Used for "logout from all devices" functionality
//
// Scoped by user_id only (refresh_tokens has no tenant column). Callers MUST
// tenant-authorize the userID before calling.
// ============================================================================
func (r *Repository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	query := `
		DELETE FROM {{schema}}.refresh_tokens
		WHERE user_id = $1
	`

	_, err := r.rw.ExecContext(ctx, r.q(query), userID)
	if err != nil {
		return fmt.Errorf("failed to delete refresh tokens for user: %w", err)
	}

	return nil
}

// ============================================================================
// DeleteExpired - Cleanup expired refresh tokens
// Should be run periodically (e.g., via cron job) to maintain database hygiene
// Returns the number of tokens deleted
// ============================================================================
func (r *Repository) DeleteExpired(ctx context.Context) (int64, error) {
	query := `
		DELETE FROM {{schema}}.refresh_tokens
		WHERE expires_at < $1
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired refresh tokens: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected, nil
}
