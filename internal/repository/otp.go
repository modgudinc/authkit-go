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

// VerificationCode represents an OTP code for email verification. The OTP itself
// is stored only as a keyed HMAC (CodeHash), never in plaintext.
type VerificationCode struct {
	TenantID  string    `json:"tenant_id" db:"tenant_id"`
	Email     string    `json:"email" db:"email"`
	CodeHash  string    `json:"-" db:"code_hash"` // HMAC-SHA256 of the code; never the plaintext
	Purpose   string    `json:"purpose" db:"purpose"`
	Attempts  int       `json:"attempts" db:"attempts"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// CreateVerificationCodeRequest contains the data needed to create a new OTP code.
// CodeHash is the keyed HMAC of the plaintext code (the service hashes it before
// calling); the repository never sees or stores the plaintext.
type CreateVerificationCodeRequest struct {
	TenantID  string
	Email     string
	CodeHash  string
	Purpose   string
	ExpiresAt time.Time
}

// OTPConsumeResult is the outcome of attempting to consume (validate) an OTP.
type OTPConsumeResult int

const (
	// OTPConsumeInvalid means no active code matched (wrong code, wrong
	// tenant/email/purpose, expired, or not found). The code, if any, was not
	// consumed; the failed attempt may have been counted.
	OTPConsumeInvalid OTPConsumeResult = iota
	// OTPConsumeValid means the code matched and was consumed (single-use).
	OTPConsumeValid
	// OTPConsumeLockedOut means the code had reached the maximum number of failed
	// attempts and has been invalidated; the caller must request a new code.
	OTPConsumeLockedOut
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
func (r *Repository) UpsertVerificationCode(ctx context.Context, req CreateVerificationCodeRequest, rateLimit time.Duration) (stored bool, err error) {
	query := `
		INSERT INTO {{schema}}.verification_codes (
			tenant_id, email, code_hash, purpose, attempts, expires_at, created_at
		)
		VALUES ($1, $2, $3, $4, 0, $5, $6)
		ON CONFLICT (tenant_id, email, purpose)
		DO UPDATE SET
			code_hash = EXCLUDED.code_hash,
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
		req.CodeHash,
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
// The code hash is deliberately NOT selected here — the rate-limit check only
// needs created_at, and the stored hash is only ever read back under a FOR UPDATE
// row lock by ConsumeVerificationCode for the constant-time match.
// ============================================================================
func (r *Repository) GetVerificationCode(ctx context.Context, tenantID, email, purpose string) (*VerificationCode, error) {
	query := `
		SELECT tenant_id, email, purpose, attempts, expires_at, created_at
		FROM {{schema}}.verification_codes
		WHERE tenant_id = $1
		  AND email = $2
		  AND purpose = $3
	`

	var vc VerificationCode
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
//   - on a code that has already reached maxAttempts: reports lockout (the row is
//     retained — see below),
//   - on a correct code: deletes it and reports OTPConsumeValid (single-use),
//   - on a wrong code: increments attempts; if that reaches maxAttempts the code is
//     locked out (row retained) and it reports OTPConsumeLockedOut, otherwise
//     OTPConsumeInvalid.
//
// A locked-out code's row is deliberately NOT deleted: its created_at keeps
// enforcing the generation rate limit, so repeatedly failing a code cannot reset
// the per-(tenant, email, purpose) cooldown and drive unlimited OTP resends. The
// row is replaced by the next generation once the cooldown elapses, and removed by
// DeleteExpiredVerificationCodes at expiry.
//
// The code comparison is constant-time to avoid leaking match progress via timing.
// codeHash is the keyed HMAC of the user-supplied code (the service hashes it
// before calling); the stored value is the same HMAC, so the compare is
// hash-to-hash. maxAttempts <= 0 disables lockout (attempts are not enforced).
// ============================================================================
func (r *Repository) ConsumeVerificationCode(ctx context.Context, tenantID, email, codeHash, purpose string, maxAttempts int) (OTPConsumeResult, error) {
	tx, err := r.rw.BeginTx(ctx, nil)
	if err != nil {
		return OTPConsumeInvalid, fmt.Errorf("failed to begin verification code consumption: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	selectQuery := `
		SELECT code_hash, attempts, expires_at
		FROM {{schema}}.verification_codes
		WHERE tenant_id = $1
		  AND email = $2
		  AND purpose = $3
		FOR UPDATE
	`

	var storedHash string
	var attempts int
	var expiresAt time.Time
	err = tx.QueryRowContext(ctx, r.q(selectQuery), tenantID, email, purpose).Scan(&storedHash, &attempts, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// No active code for this (tenant, email, purpose); nothing to consume.
			if cErr := tx.Commit(); cErr != nil {
				return OTPConsumeInvalid, fmt.Errorf("failed to commit verification code consumption: %w", cErr)
			}
			committed = true
			return OTPConsumeInvalid, nil
		}
		return OTPConsumeInvalid, fmt.Errorf("failed to read verification code: %w", err)
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
			return OTPConsumeInvalid, fmt.Errorf("failed to delete expired verification code: %w", err)
		}
		return OTPConsumeInvalid, nil
	}

	// Already locked out: the row stays put — its created_at still enforces the
	// generation cooldown (see the method doc) — so just release the lock and report it.
	if maxAttempts > 0 && attempts >= maxAttempts {
		if err := tx.Commit(); err != nil {
			return OTPConsumeInvalid, fmt.Errorf("failed to commit verification code consumption: %w", err)
		}
		committed = true
		return OTPConsumeLockedOut, nil
	}

	// Constant-time comparison to avoid timing side channels (both sides are HMACs).
	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(codeHash)) == 1 {
		if err := deleteAndCommit(); err != nil {
			return OTPConsumeInvalid, fmt.Errorf("failed to consume verification code: %w", err)
		}
		return OTPConsumeValid, nil
	}

	// Wrong code: persist the incremented attempt count. The row is retained even
	// when this trips the lockout, so its created_at keeps enforcing the generation
	// cooldown (see the method doc) — a burst of wrong guesses cannot wipe it to
	// drive fresh OTP emails on demand.
	newAttempts := attempts + 1
	updateQuery := `
		UPDATE {{schema}}.verification_codes
		SET attempts = $4
		WHERE tenant_id = $1
		  AND email = $2
		  AND purpose = $3
	`
	if _, err := tx.ExecContext(ctx, r.q(updateQuery), tenantID, email, purpose, newAttempts); err != nil {
		return OTPConsumeInvalid, fmt.Errorf("failed to record failed verification attempt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return OTPConsumeInvalid, fmt.Errorf("failed to commit verification code consumption: %w", err)
	}
	committed = true

	if maxAttempts > 0 && newAttempts >= maxAttempts {
		return OTPConsumeLockedOut, nil
	}
	return OTPConsumeInvalid, nil
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

	return requireRowsAffected(result, fmt.Errorf("verification code not found: %w", model.ErrNotFound))
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
