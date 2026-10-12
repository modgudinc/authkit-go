// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/modgudinc/authkit-go/internal/repository"
)

// WithTx returns a copy of ctx that makes authkit run its queries in tx, so what a
// call changes commits or rolls back with the caller's own writes in the same
// transaction: an outbox row recording the change, say. tx must be a transaction on
// the identity schema's database (Config.DBConnection). Where authkit would begin a
// transaction of its own, it sets a savepoint in tx instead, and reads go to tx too,
// so they see what the caller wrote before them.
//
// Signing in and checking a credential ignore tx and commit on their own, because
// what they record (failed attempts, lockouts, revoked token families, used codes and
// signature counters) must stay recorded whatever the caller does with tx: the
// AuthService, InstallationAuthService and VerifiedLoginService sign-ins,
// AuthService.MintWorkspaceToken, RefreshToken, ValidateJWT and ChangePassword, the
// TokenService calls that issue or check a token, OTPService.Generate and Validate,
// TwoFactorService.ConfirmTOTP, Verify and CompleteSecondFactor,
// APIKeyService.Validate and PasskeyService.RecordUse.
//
// An error from a call may leave tx unusable, since Postgres aborts a transaction
// whose statement fails, so roll tx back when a call fails. A transaction-scoped
// advisory lock authkit takes is held until tx ends. See docs/transactions.md.
func WithTx(ctx context.Context, tx *sql.Tx) context.Context {
	return repository.WithTx(ctx, tx)
}

// InTx runs fn in a new transaction on the read-write identity database, with a
// context that makes authkit's calls run in it (WithTx), and commits it if fn returns
// nil. Otherwise it rolls the transaction back and returns fn's error.
func (k *AuthKit) InTx(ctx context.Context, fn func(ctx context.Context, tx *sql.Tx) error) error {
	tx, err := k.rwConnection.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	if err := fn(WithTx(ctx, tx), tx); err != nil {
		if rerr := tx.Rollback(); rerr != nil && !errors.Is(rerr, sql.ErrTxDone) {
			return errors.Join(err, fmt.Errorf("roll back: %w", rerr))
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}
