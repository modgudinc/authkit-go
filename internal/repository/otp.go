// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/modgudinc/authkit-go/model"
)

// OTP Repository Methods:
//
// Code Management:
// - Upsert       - Creates or updates a verification code for (tenant, email, purpose)
// - Get          - Retrieves a verification code by (tenant, email, purpose)
// - Verify       - Verifies an OTP code (checks existence, match, and expiration)
// - Consume      - Atomically validates and consumes a code, counting failed attempts
// - Delete       - Deletes a verification code after use
//
// Maintenance:
// - DeleteExpired - Cleanup method to remove expired verification codes
//
// All single-code operations are scoped by tenant_id so a code issued in one
// tenant can never be read, overwritten, or verified in another tenant.

// ============================================================================
// Upsert - Creates or updates a verification code for (tenant, email, purpose)
// Uses UPSERT to replace any existing code for the same key and resets the
// failed-attempt counter so a freshly issued code starts with a full budget.
// ============================================================================
// UpsertVerificationCode atomically issues a code for (tenant, email, purpose),
// enforcing the generation rate limit in the same statement to avoid a
// check-then-write TOCTOU. The ON CONFLICT update only replaces an existing code
// once it is older than rateLimit; if a more recent code exists the update
// affects zero rows and stored is false (rate-limited). A fresh insert (no
// existing code) always stores. rateLimit <= 0 disables the limit.
func (r *Repository) UpsertVerificationCode(ctx context.Context, req model.CreateVerificationCodeRequest, rateLimit time.Duration) (stored bool, err error) {
	query := `
		INSERT INTO {{schema}}.verification_codes (
			tenant_id, email, code, purpose, attempts, expires_at, created_at
		)
		VALUES ($1, $2, $3, $4, 0, $5, $6)
		ON CONFLICT (tenant_id, email, purpose)
		DO UPDATE SET
			code = EXCLUDED.code,
			attempts = 0,
			expires_at = EXCLUDED.expires_at,
			created_at = EXCLUDED.created_at
		WHERE verification_codes.created_at <= $7
	`

	now := time.Now()
	cutoff := now.Add(-rateLimit) // existing code must be at least this old to be replaced
	result, err := r.rw.ExecContext(ctx, r.q(query),
		req.TenantID,
		req.Email,
		req.Code,
		req.Purpose,
		req.ExpiresAt,
		now,
		cutoff,
	)
	if err != nil {
		return false, fmt.Errorf("failed to upsert verification code: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected > 0, nil
}

// ============================================================================
// Get - Retrieves a verification code by (tenant, email, purpose)
// Returns the full VerificationCode record including expiration and attempts.
//
// Reads from the PRIMARY (rw), not a read replica: the sole caller is OTP
// generation's rate-limit check, and reading a replica there would let
// replication lag hide a just-issued code and bypass the limit. Returns
// model.ErrNotFound (wrapped) when no code exists for the key.
//
// The plaintext code is deliberately NOT selected here — the rate-limit check
// only needs created_at, and the code is only ever read back under a FOR UPDATE
// row lock by ConsumeVerificationCode for the constant-time match. Keeping the
// code out of this read narrows where the plaintext value is exposed.
// ============================================================================
func (r *Repository) GetVerificationCode(ctx context.Context, tenantID, email, purpose string) (*model.VerificationCode, error) {
	query := `
		SELECT tenant_id, email, purpose, attempts, expires_at, created_at
		FROM {{schema}}.verification_codes
		WHERE tenant_id = $1
		  AND email = $2
		  AND purpose = $3
	`

	var vc model.VerificationCode
	err := r.rw.QueryRowContext(ctx, r.q(query), tenantID, email, purpose).Scan(
		&vc.TenantID,
		&vc.Email,
		&vc.Purpose,
		&vc.Attempts,
		&vc.ExpiresAt,
		&vc.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("verification code not found: %w", model.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get verification code: %w", err)
	}

	return &vc, nil
}

// ============================================================================
// Consume - Atomically validates and consumes a verification code.
//
// Within a single transaction (row locked FOR UPDATE) it:
//   - rejects and deletes an expired code,
//   - rejects and deletes a code that has already reached maxAttempts (lockout),
//   - on a correct code: deletes it and reports OTPConsumeValid (single-use),
//   - on a wrong code: increments attempts, and if that reaches maxAttempts
//     deletes the code and reports OTPConsumeLockedOut, otherwise OTPConsumeInvalid.
//
// The code comparison is constant-time to avoid leaking match progress via timing.
// maxAttempts <= 0 disables lockout (attempts are not enforced).
// ============================================================================
func (r *Repository) ConsumeVerificationCode(ctx context.Context, tenantID, email, code, purpose string, maxAttempts int) (model.OTPConsumeResult, error) {
	tx, err := r.rw.BeginTx(ctx, nil)
	if err != nil {
		return model.OTPConsumeInvalid, fmt.Errorf("failed to begin verification code consumption: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	selectQuery := `
		SELECT code, attempts, expires_at
		FROM {{schema}}.verification_codes
		WHERE tenant_id = $1
		  AND email = $2
		  AND purpose = $3
		FOR UPDATE
	`

	var storedCode string
	var attempts int
	var expiresAt time.Time
	err = tx.QueryRowContext(ctx, r.q(selectQuery), tenantID, email, purpose).Scan(&storedCode, &attempts, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// No active code for this (tenant, email, purpose); nothing to consume.
			if cErr := tx.Commit(); cErr != nil {
				return model.OTPConsumeInvalid, fmt.Errorf("failed to commit verification code consumption: %w", cErr)
			}
			committed = true
			return model.OTPConsumeInvalid, nil
		}
		return model.OTPConsumeInvalid, fmt.Errorf("failed to read verification code: %w", err)
	}

	deleteQuery := `
		DELETE FROM {{schema}}.verification_codes
		WHERE tenant_id = $1
		  AND email = $2
		  AND purpose = $3
	`

	deleteAndCommit := func() error {
		if _, err := tx.ExecContext(ctx, r.q(deleteQuery), tenantID, email, purpose); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		committed = true
		return nil
	}

	// Expired: clean up and report invalid.
	if time.Now().After(expiresAt) {
		if err := deleteAndCommit(); err != nil {
			return model.OTPConsumeInvalid, fmt.Errorf("failed to delete expired verification code: %w", err)
		}
		return model.OTPConsumeInvalid, nil
	}

	// Already exhausted: invalidate the code and report lockout.
	if maxAttempts > 0 && attempts >= maxAttempts {
		if err := deleteAndCommit(); err != nil {
			return model.OTPConsumeInvalid, fmt.Errorf("failed to delete exhausted verification code: %w", err)
		}
		return model.OTPConsumeLockedOut, nil
	}

	// Constant-time comparison to avoid timing side channels.
	if subtle.ConstantTimeCompare([]byte(storedCode), []byte(code)) == 1 {
		if err := deleteAndCommit(); err != nil {
			return model.OTPConsumeInvalid, fmt.Errorf("failed to consume verification code: %w", err)
		}
		return model.OTPConsumeValid, nil
	}

	// Wrong code: count the failed attempt; lock out if it reaches the cap.
	newAttempts := attempts + 1
	if maxAttempts > 0 && newAttempts >= maxAttempts {
		if err := deleteAndCommit(); err != nil {
			return model.OTPConsumeInvalid, fmt.Errorf("failed to delete verification code after final attempt: %w", err)
		}
		return model.OTPConsumeLockedOut, nil
	}

	updateQuery := `
		UPDATE {{schema}}.verification_codes
		SET attempts = $4
		WHERE tenant_id = $1
		  AND email = $2
		  AND purpose = $3
	`
	if _, err := tx.ExecContext(ctx, r.q(updateQuery), tenantID, email, purpose, newAttempts); err != nil {
		return model.OTPConsumeInvalid, fmt.Errorf("failed to record failed verification attempt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return model.OTPConsumeInvalid, fmt.Errorf("failed to commit verification code consumption: %w", err)
	}
	committed = true

	return model.OTPConsumeInvalid, nil
}

// ============================================================================
// Delete - Deletes a verification code for (tenant, email, purpose)
// Used to explicitly revoke a pending code before it is used.
// ============================================================================
func (r *Repository) DeleteVerificationCode(ctx context.Context, tenantID, email, purpose string) error {
	query := `
		DELETE FROM {{schema}}.verification_codes
		WHERE tenant_id = $1
		  AND email = $2
		  AND purpose = $3
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), tenantID, email, purpose)
	if err != nil {
		return fmt.Errorf("failed to delete verification code: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("verification code not found: %w", model.ErrNotFound)
	}

	return nil
}

// ============================================================================
// DeleteExpired - Cleanup method to remove expired verification codes
// Should be run periodically (e.g., via cron job) to maintain database hygiene
// Returns the number of expired codes deleted
// ============================================================================
func (r *Repository) DeleteExpiredVerificationCodes(ctx context.Context) (int64, error) {
	query := `
		DELETE FROM {{schema}}.verification_codes
		WHERE expires_at <= $1
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired verification codes: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected, nil
}
