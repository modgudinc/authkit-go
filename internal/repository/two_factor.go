// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/modgudinc/authkit-go/model"
)

// Two-factor repository methods (migration 000009): a user's authenticator-app
// (TOTP) factor, their recovery codes, and password logins waiting for a second
// factor. Every read that decides a sign-in uses the primary.

// TOTPFactor is a user's stored authenticator-app factor. SecretCiphertext is
// encrypted by the service; the repository never sees the secret.
type TOTPFactor struct {
	UserID           string
	SecretCiphertext string
	ConfirmedAt      *time.Time
	LastUsedStep     int64
	CreatedAt        time.Time
}

// SecondFactorChallenge is a password login waiting for its second factor. Login
// is the service's encoding of the request to finish.
type SecondFactorChallenge struct {
	UserID    string
	Login     []byte
	ExpiresAt time.Time
}

// GetTOTPFactor returns userID's factor, confirmed or not, from the primary, or
// model.ErrNotFound.
func (r *Repository) GetTOTPFactor(ctx context.Context, userID string) (*TOTPFactor, error) {
	var f TOTPFactor
	err := r.rw.QueryRowContext(ctx, r.q(`
		SELECT user_id, secret_ciphertext, confirmed_at, last_used_step, created_at
		FROM {{schema}}.totp_factors WHERE user_id=$1`), userID).
		Scan(&f.UserID, &f.SecretCiphertext, &f.ConfirmedAt, &f.LastUsedStep, &f.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("no authenticator app: %w", model.ErrNotFound)
	}
	return &f, err
}

// TwoFactorEnabled reports, from the primary, whether userID has a confirmed
// factor, which makes their password logins need a second factor.
func (r *Repository) TwoFactorEnabled(ctx context.Context, userID string) (bool, error) {
	var enabled bool
	err := r.rw.QueryRowContext(ctx, r.q(`
		SELECT EXISTS(SELECT 1 FROM {{schema}}.totp_factors WHERE user_id=$1 AND confirmed_at IS NOT NULL)`),
		userID).Scan(&enabled)
	return enabled, err
}

// SavePendingTOTP stores a new, unconfirmed factor for userID, replacing an
// unconfirmed one. It returns model.ErrTwoFactorAlreadyEnabled when the user has a
// confirmed factor, and model.ErrNotFound for an unknown user.
func (r *Repository) SavePendingTOTP(ctx context.Context, userID, secretCiphertext string) error {
	result, err := r.rw.ExecContext(ctx, r.q(`
		INSERT INTO {{schema}}.totp_factors AS f (user_id, secret_ciphertext) VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE
		SET secret_ciphertext = EXCLUDED.secret_ciphertext, last_used_step = 0, created_at = NOW()
		WHERE f.confirmed_at IS NULL`), userID, secretCiphertext)
	if isForeignKeyViolation(err) {
		return fmt.Errorf("user not found: %w", model.ErrNotFound)
	}
	if err != nil {
		return err
	}
	return requireRowsAffected(result, model.ErrTwoFactorAlreadyEnabled)
}

// ConfirmTOTP turns userID's pending factor on, recording step as its first used
// step, and replaces their recovery codes with codeHashes, in one transaction.
// secretCiphertext is the stored secret the code was checked against. It returns
// model.ErrNotFound when there is no pending factor with that secret (a new
// enrollment replaced it), or step was not after the last one used.
func (r *Repository) ConfirmTOTP(ctx context.Context, userID, secretCiphertext string, step int64, codeHashes []string) error {
	tx, err := r.rw.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, r.q(`
		UPDATE {{schema}}.totp_factors SET confirmed_at = NOW(), last_used_step = $2
		WHERE user_id = $1 AND confirmed_at IS NULL AND last_used_step < $2 AND secret_ciphertext = $3`),
		userID, step, secretCiphertext)
	if err != nil {
		return err
	}
	if err := requireRowsAffected(result, fmt.Errorf("no pending authenticator app: %w", model.ErrNotFound)); err != nil {
		return err
	}
	if err := r.replaceRecoveryCodes(ctx, tx, userID, codeHashes); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) replaceRecoveryCodes(ctx context.Context, tx *sql.Tx, userID string, codeHashes []string) error {
	if _, err := tx.ExecContext(ctx, r.q("DELETE FROM {{schema}}.recovery_codes WHERE user_id=$1"), userID); err != nil {
		return err
	}
	for _, h := range codeHashes {
		if _, err := tx.ExecContext(ctx, r.q(
			"INSERT INTO {{schema}}.recovery_codes (user_id, code_hash) VALUES ($1, $2)"), userID, h); err != nil {
			return err
		}
	}
	return nil
}

// ReplaceRecoveryCodes replaces userID's recovery codes with codeHashes. It returns
// model.ErrNotFound when the user has no confirmed factor.
func (r *Repository) ReplaceRecoveryCodes(ctx context.Context, userID string, codeHashes []string) error {
	tx, err := r.rw.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var confirmed bool
	err = tx.QueryRowContext(ctx, r.q(`
		SELECT confirmed_at IS NOT NULL FROM {{schema}}.totp_factors WHERE user_id=$1 FOR UPDATE`), userID).Scan(&confirmed)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !confirmed) {
		return fmt.Errorf("two-factor is not on: %w", model.ErrNotFound)
	}
	if err != nil {
		return err
	}
	if err := r.replaceRecoveryCodes(ctx, tx, userID, codeHashes); err != nil {
		return err
	}
	return tx.Commit()
}

// UseTOTPStep records that a code for step was accepted for userID's confirmed
// factor. It returns false, changing nothing, when the step is not after the last
// one used (a replayed or older code) or the factor is not on.
func (r *Repository) UseTOTPStep(ctx context.Context, userID string, step int64) (bool, error) {
	result, err := r.rw.ExecContext(ctx, r.q(`
		UPDATE {{schema}}.totp_factors SET last_used_step = $2
		WHERE user_id = $1 AND confirmed_at IS NOT NULL AND last_used_step < $2`), userID, step)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

// UseRecoveryCode spends one of userID's unused recovery codes. It returns false
// when no unused code has the hash.
func (r *Repository) UseRecoveryCode(ctx context.Context, userID, codeHash string) (bool, error) {
	result, err := r.rw.ExecContext(ctx, r.q(`
		UPDATE {{schema}}.recovery_codes SET used_at = NOW()
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`), userID, codeHash)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

// DeleteTwoFactor removes userID's factor, recovery codes and waiting logins. It
// returns model.ErrNotFound when the user has no factor, confirmed or not.
func (r *Repository) DeleteTwoFactor(ctx context.Context, userID string) error {
	tx, err := r.rw.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, r.q("DELETE FROM {{schema}}.totp_factors WHERE user_id=$1"), userID)
	if err != nil {
		return err
	}
	if err := requireRowsAffected(result, fmt.Errorf("no authenticator app: %w", model.ErrNotFound)); err != nil {
		return err
	}
	for _, table := range []string{"recovery_codes", "second_factor_challenges"} {
		if _, err := tx.ExecContext(ctx, r.q("DELETE FROM {{schema}}."+table+" WHERE user_id=$1"), userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// TwoFactorStatus returns userID's two-factor state from the replica.
func (r *Repository) TwoFactorStatus(ctx context.Context, userID string) (*model.TwoFactorStatus, error) {
	var status model.TwoFactorStatus
	err := r.ro.QueryRowContext(ctx, r.q(`
		SELECT
			(SELECT confirmed_at FROM {{schema}}.totp_factors WHERE user_id=$1),
			(SELECT count(*) FROM {{schema}}.recovery_codes WHERE user_id=$1 AND used_at IS NULL)`),
		userID).Scan(&status.EnabledAt, &status.RecoveryCodesLeft)
	if err != nil {
		return nil, err
	}
	status.Enabled = status.EnabledAt != nil
	return &status, nil
}

// InsertSecondFactorChallenge stores a password login waiting for its second
// factor, keyed by the hash of its challenge, and drops the user's expired ones.
func (r *Repository) InsertSecondFactorChallenge(ctx context.Context, tokenHash, userID string, login []byte, expiresAt time.Time) error {
	if _, err := r.rw.ExecContext(ctx, r.q(
		"DELETE FROM {{schema}}.second_factor_challenges WHERE user_id=$1 AND expires_at < NOW()"), userID); err != nil {
		return err
	}
	_, err := r.rw.ExecContext(ctx, r.q(`
		INSERT INTO {{schema}}.second_factor_challenges (token_hash, user_id, login, expires_at)
		VALUES ($1, $2, $3::jsonb, $4)`), tokenHash, userID, string(login), expiresAt)
	return err
}

// GetSecondFactorChallenge returns the waiting login with this challenge hash from
// the primary, expired or not, or model.ErrNotFound.
func (r *Repository) GetSecondFactorChallenge(ctx context.Context, tokenHash string) (*SecondFactorChallenge, error) {
	var c SecondFactorChallenge
	err := r.rw.QueryRowContext(ctx, r.q(`
		SELECT user_id, login, expires_at FROM {{schema}}.second_factor_challenges WHERE token_hash=$1`), tokenHash).
		Scan(&c.UserID, &c.Login, &c.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("no such login waiting: %w", model.ErrNotFound)
	}
	return &c, err
}

// DeleteSecondFactorChallenge removes a waiting login and reports whether this call
// removed it, so only one caller can finish it.
func (r *Repository) DeleteSecondFactorChallenge(ctx context.Context, tokenHash string) (bool, error) {
	result, err := r.rw.ExecContext(ctx, r.q(
		"DELETE FROM {{schema}}.second_factor_challenges WHERE token_hash=$1"), tokenHash)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

// CleanupSecondFactorChallenges deletes waiting logins that expired before now and
// returns how many.
func (r *Repository) CleanupSecondFactorChallenges(ctx context.Context, now time.Time) (int64, error) {
	result, err := r.rw.ExecContext(ctx, r.q(
		"DELETE FROM {{schema}}.second_factor_challenges WHERE expires_at < $1"), now)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
