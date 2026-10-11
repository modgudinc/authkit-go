//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

// A refresh for a disabled or locked account is refused before anything is consumed
// and deletes nothing: a lock pauses the account's refresh tokens, and a token stolen
// before the lock is still caught as reuse.

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	authkit "github.com/modgudinc/authkit-go"
	"github.com/modgudinc/authkit-go/internal/service"
	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
)

// liveRefreshTokens counts the user's refresh tokens that are neither revoked nor
// expired, bound ones included.
func liveRefreshTokens(t *testing.T, db *sql.DB, userID string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM authkit.refresh_tokens
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()`, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// lockOut trips the failed-login lockout with wrong passwords, as anyone who knows
// the email can.
func lockOut(t *testing.T, db *sql.DB, k *authkit.AuthKit, userID string) {
	t.Helper()
	for i := 0; i < service.MaxFailedLoginAttempts; i++ {
		_, err := k.AuthService().Login(context.Background(), model.LoginRequest{
			Email: "admin@ready.test", Password: "WrongPass1!", TenantID: "ready.test",
		})
		if !errors.Is(err, model.ErrInvalidCredentials) {
			t.Fatalf("wrong password %d: %v", i+1, err)
		}
	}
	var locked bool
	if err := db.QueryRow("SELECT is_locked FROM authkit.users WHERE id = $1", userID).Scan(&locked); err != nil || !locked {
		t.Fatalf("lockout: locked=%v err=%v", locked, err)
	}
}

// liftLock lets the lockout run out.
func liftLock(t *testing.T, db *sql.DB, userID string) {
	t.Helper()
	if _, err := db.Exec("UPDATE authkit.users SET locked_until = now() - interval '1 second' WHERE id = $1", userID); err != nil {
		t.Fatal(err)
	}
}

func refreshReady(k *authkit.AuthKit, token string) (*model.RefreshResponse, error) {
	return k.AuthService().RefreshToken(context.Background(), model.RefreshRequest{RefreshToken: token, TenantID: "ready.test"})
}

func TestLockoutPausesRefreshTokens(t *testing.T) {
	for name, mode := range map[string]authkit.SessionMode{"disabled": authkit.SessionDisabled, "optional": authkit.SessionOptional} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			m := &countingMetrics{}
			db, _, k, userID := readinessFixture(t, mode, nil, m)
			phone := readinessLogin(t, k, nil).RefreshToken
			laptop := readinessLogin(t, k, nil).RefreshToken
			var bound string
			if mode == authkit.SessionOptional {
				// The legacy rotation used to delete the bound session's token too.
				resp, err := k.InstallationAuthService().LoginWithInstallation(ctx, model.InstallationLoginRequest{
					LoginRequest: model.LoginRequest{Email: "admin@ready.test", Password: "ValidPass1!", TenantID: "ready.test"},
					Installation: model.InstallationBinding{InstallationID: "desk-1"},
				})
				if err != nil {
					t.Fatal(err)
				}
				bound = resp.RefreshToken
			}
			live := liveRefreshTokens(t, db, userID)

			lockOut(t, db, k, userID)
			_, err := refreshReady(k, phone)
			if !errors.Is(err, model.ErrInvalidRefreshToken) || !errors.Is(err, model.ErrAccountLocked) {
				t.Fatalf("refresh while locked: %v, want ErrInvalidRefreshToken and ErrAccountLocked", err)
			}
			if _, err := k.TokenService().ValidateRefreshToken(ctx, laptop); !errors.Is(err, model.ErrInvalidRefreshToken) || !errors.Is(err, model.ErrAccountLocked) {
				t.Fatalf("validate while locked: %v, want ErrInvalidRefreshToken and ErrAccountLocked", err)
			}
			if got := liveRefreshTokens(t, db, userID); got != live {
				t.Fatalf("%d live refresh tokens after a refresh while locked, want %d", got, live)
			}

			liftLock(t, db, userID)
			for name, token := range map[string]string{"phone": phone, "laptop": laptop, "bound": bound} {
				if token == "" {
					continue
				}
				if _, err := refreshReady(k, token); err != nil {
					t.Errorf("%s after the lock: %v", name, err)
				}
			}
			if n := m.get(metrics.CounterRefreshReuse); n != 0 {
				t.Errorf("reuse counted %d times", n)
			}
		})
	}
}

func TestStolenTokenIsReuseAfterALockout(t *testing.T) {
	m := &countingMetrics{}
	db, _, k, userID := readinessFixture(t, authkit.SessionDisabled, nil, m)
	stolen := readinessLogin(t, k, nil).RefreshToken
	owner, err := refreshReady(k, stolen)
	if err != nil {
		t.Fatal(err)
	}

	// The owner's device refreshes during a lockout. That used to delete every token
	// the user had, so the thief's replay below read as an unknown token.
	lockOut(t, db, k, userID)
	if _, err := refreshReady(k, owner.RefreshToken); !errors.Is(err, model.ErrAccountLocked) {
		t.Fatalf("owner's refresh while locked: %v", err)
	}

	_, err = refreshReady(k, stolen)
	if !errors.Is(err, model.ErrRefreshTokenReuse) {
		t.Fatalf("replay of the stolen token: %v, want ErrRefreshTokenReuse", err)
	}
	if n := m.get(metrics.CounterRefreshReuse); n != 1 {
		t.Errorf("reuse counted %d times, want 1", n)
	}
	if got := liveRefreshTokens(t, db, userID); got != 0 {
		t.Errorf("%d live refresh tokens after reuse, want the family revoked", got)
	}
}

func TestDisabledAccountRefreshConsumesNothing(t *testing.T) {
	ctx := context.Background()
	db, repo, k, userID := readinessFixture(t, authkit.SessionDisabled, nil, nil)
	token := readinessLogin(t, k, nil).RefreshToken
	// The repository's Disable leaves the tokens alone (UserService.Disable revokes
	// them), so the refresh reaches the account check.
	if err := repo.Disable(ctx, userID); err != nil {
		t.Fatal(err)
	}
	_, err := refreshReady(k, token)
	if !errors.Is(err, model.ErrInvalidRefreshToken) || !errors.Is(err, model.ErrAccountDisabled) {
		t.Fatalf("refresh while disabled: %v, want ErrInvalidRefreshToken and ErrAccountDisabled", err)
	}
	if got := liveRefreshTokens(t, db, userID); got != 1 {
		t.Fatalf("%d live refresh tokens after a refresh while disabled, want 1", got)
	}
	if _, err := k.TokenService().ValidateRefreshToken(ctx, token); !errors.Is(err, model.ErrAccountDisabled) {
		t.Fatalf("validate while disabled: %v", err)
	}
}
