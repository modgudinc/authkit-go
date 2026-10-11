//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

// A password set by UserService.SetPassword ends the access tokens and the logins
// waiting for a second factor that came before it, and TwoFactorService.Verify
// refuses a locked or disabled account before it checks a code.

import (
	"context"
	"testing"

	authkit "github.com/modgudinc/authkit-go"
)

func TestSetPasswordEndsTokensAndPendingSecondFactor(t *testing.T) {
	db, k, _, userID := twoFactorFixture(t, authkit.SessionDisabled)
	ctx := context.Background()
	secret, _ := turnOnTwoFactor(t, k, userID)

	_, err := historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant)
	signedIn, err := complete(k, challengeFrom(t, err), freshCode(t, db, secret, userID))
	if err != nil {
		t.Fatal(err)
	}
	// A second login passed the old password and waits for its code.
	_, err = historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant)
	pending := challengeFrom(t, err)

	hash, err := k.PasswordService().HashPassword("ResetPass1!")
	if err != nil {
		t.Fatal(err)
	}
	if err := k.UserService().SetPassword(ctx, userID, hash); err != nil {
		t.Fatal(err)
	}

	_, err = k.AuthService().ValidateJWT(ctx, signedIn.AccessToken)
	requireError(t, err, authkit.ErrTokenRevoked)
	_, err = complete(k, pending, freshCode(t, db, secret, userID))
	requireError(t, err, authkit.ErrInvalidCredentials)

	// The new password signs in.
	_, err = historyLogin(k, authkit.SessionDisabled, "ResetPass1!", historyTenant)
	if _, err := complete(k, challengeFrom(t, err), freshCode(t, db, secret, userID)); err != nil {
		t.Fatalf("sign-in with the new password: %v", err)
	}
}

func TestVerifyRefusesLockedAndDisabledAccounts(t *testing.T) {
	db, k, _, userID := twoFactorFixture(t, authkit.SessionDisabled)
	ctx := context.Background()
	secret, _ := turnOnTwoFactor(t, k, userID)

	for range 5 {
		err := k.TwoFactorService().Verify(ctx, userID, wrongCode(t, secret))
		requireError(t, err, authkit.ErrInvalidSecondFactor)
	}
	if failed, locked := userCounters(t, db, userID); failed != 5 || !locked {
		t.Fatalf("failed %d, locked %v after five wrong codes", failed, locked)
	}
	// Locked: neither a wrong code nor the right one is checked.
	err := k.TwoFactorService().Verify(ctx, userID, wrongCode(t, secret))
	requireError(t, err, authkit.ErrAccountLocked)
	err = k.TwoFactorService().Verify(ctx, userID, freshCode(t, db, secret, userID))
	requireError(t, err, authkit.ErrAccountLocked)
	if failed, _ := userCounters(t, db, userID); failed != 5 {
		t.Fatalf("failed count %d after codes tried while locked, want 5", failed)
	}

	// Once the lock runs out, the right code is accepted.
	if _, err := db.Exec("UPDATE authkit.users SET locked_until = now() - interval '1 second' WHERE id = $1", userID); err != nil {
		t.Fatal(err)
	}
	if err := k.TwoFactorService().Verify(ctx, userID, freshCode(t, db, secret, userID)); err != nil {
		t.Fatalf("Verify after the lock ran out: %v", err)
	}

	if _, err := db.Exec("UPDATE authkit.users SET is_enabled = false WHERE id = $1", userID); err != nil {
		t.Fatal(err)
	}
	err = k.TwoFactorService().Verify(ctx, userID, freshCode(t, db, secret, userID))
	requireError(t, err, authkit.ErrAccountDisabled)
}
