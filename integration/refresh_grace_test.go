//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	authkit "github.com/modgudinc/authkit-go"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
)

const (
	graceTenant = "grace.test"
	gracePeriod = time.Minute
)

// graceModes runs a test against legacy refresh tokens (sessions disabled) and
// against installation-bound sessions, which rotate through different code.
var graceModes = []authkit.SessionMode{authkit.SessionDisabled, authkit.SessionRequired}

// graceFixture builds the schema with migration 000006 and seeds
// admin@grace.test, then returns a kit with JWTConfig.RefreshGracePeriod set.
func graceFixture(t *testing.T, mode authkit.SessionMode) (*sql.DB, *authkit.AuthKit, *countingMetrics, string) {
	t.Helper()
	db := openTestDB(t)
	db.SetMaxOpenConns(12)
	t.Cleanup(func() { applyMigration(t, db, "000001_identity_schema.down.sql"); _ = db.Close() })
	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)
	if mode != authkit.SessionDisabled {
		applyMigration(t, db, "000002_installation_sessions.up.sql")
		applyMigration(t, db, "000003_session_sign_in.up.sql")
	}
	applyMigration(t, db, "000006_refresh_token_replacement.up.sql")
	repo := repository.New(db, db)
	userID := createTenantAndUser(t, context.Background(), &repo, graceTenant)

	m := &countingMetrics{}
	namespace := ""
	if mode != authkit.SessionDisabled {
		namespace = "app"
	}
	k, err := authkit.New(authkit.Config{
		DBConnection: authkit.DatabaseConnection{IdentityRWDB: db, IdentityRODB: db},
		JWTConfig: authkit.JWTConfig{
			AccessSecret:           "integration-access-secret-at-least-32-bytes",
			RefreshTokenHMACSecret: "integration-refresh-hmac-secret-at-least-32b",
			AccessExpiry:           5 * time.Minute, RefreshExpiry: time.Hour,
			RefreshGracePeriod: gracePeriod,
		},
		APIKeyConfig:   authkit.APIKeyConfig{HMACSecret: "integration-api-hmac-secret-at-least-32-bytes"},
		PasswordConfig: authkit.PasswordConfig{BcryptCost: 4},
		SessionConfig:  authkit.SessionConfig{Mode: mode, Namespace: namespace, AbsoluteLifetime: 2 * time.Hour},
		Metrics:        m,
	})
	if err != nil {
		t.Fatal(err)
	}
	return db, k, m, userID
}

// graceLogin signs admin@grace.test in and returns the refresh token.
func graceLogin(t *testing.T, k *authkit.AuthKit, mode authkit.SessionMode) string {
	t.Helper()
	req := model.LoginRequest{Email: "admin@" + graceTenant, Password: "ValidPass1!", TenantID: graceTenant}
	if mode == authkit.SessionDisabled {
		resp, err := k.AuthService().Login(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		return resp.RefreshToken
	}
	resp, err := k.InstallationAuthService().LoginWithInstallation(context.Background(), model.InstallationLoginRequest{
		LoginRequest: req, Installation: model.InstallationBinding{InstallationID: "laptop"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp.RefreshToken
}

func graceRefresh(k *authkit.AuthKit, token string) (*model.RefreshResponse, error) {
	return k.AuthService().RefreshToken(context.Background(), model.RefreshRequest{RefreshToken: token, TenantID: graceTenant})
}

func mustRefresh(t *testing.T, k *authkit.AuthKit, token string) *model.RefreshResponse {
	t.Helper()
	resp, err := graceRefresh(k, token)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	return resp
}

// A client that lost the response to a refresh presents the old token again and
// gets a new pair; the replacement it never saw is revoked, and presenting that one
// later is reuse.
func TestRefreshGraceRetryAfterLostResponse(t *testing.T) {
	for _, mode := range graceModes {
		t.Run(modeName(mode), func(t *testing.T) {
			ctx := context.Background()
			_, k, m, _ := graceFixture(t, mode)
			rt1 := graceLogin(t, k, mode)

			lost := mustRefresh(t, k, rt1).RefreshToken
			retried := mustRefresh(t, k, rt1)
			if retried.RefreshToken == lost || retried.RefreshToken == rt1 {
				t.Fatal("a retry must issue a new refresh token")
			}
			if _, err := k.AuthService().ValidateJWT(ctx, retried.AccessToken); err != nil {
				t.Fatalf("access token from a retry: %v", err)
			}
			if got := m.get(metrics.CounterRefreshRetry); got != 1 {
				t.Fatalf("retry counter = %d, want 1", got)
			}
			if got := m.get(metrics.CounterRefreshReuse); got != 0 {
				t.Fatalf("reuse counter = %d, want 0", got)
			}

			// The retried token carries on as normal.
			next := mustRefresh(t, k, retried.RefreshToken)

			// The replacement the client never received was revoked by the retry, so
			// whoever presents it now is caught.
			if _, err := graceRefresh(k, lost); !errors.Is(err, authkit.ErrRefreshTokenReuse) {
				t.Fatalf("superseded replacement: want ErrRefreshTokenReuse, got %v", err)
			}
			if _, err := graceRefresh(k, next.RefreshToken); err == nil {
				t.Fatal("reuse must end the session for every token in it")
			}
		})
	}
}

// Once the replacement has been used, the old token is reuse as before: a thief
// replaying it after the owner refreshed is caught.
func TestRefreshGraceEndsWhenReplacementIsUsed(t *testing.T) {
	for _, mode := range graceModes {
		t.Run(modeName(mode), func(t *testing.T) {
			_, k, m, _ := graceFixture(t, mode)
			rt1 := graceLogin(t, k, mode)
			rt2 := mustRefresh(t, k, rt1).RefreshToken
			rt3 := mustRefresh(t, k, rt2).RefreshToken

			if _, err := graceRefresh(k, rt1); !errors.Is(err, authkit.ErrRefreshTokenReuse) {
				t.Fatalf("old token after its replacement was used: want ErrRefreshTokenReuse, got %v", err)
			}
			if _, err := graceRefresh(k, rt3); err == nil {
				t.Fatal("reuse must end the session for every token in it")
			}
			if got := m.get(metrics.CounterRefreshRetry); got != 0 {
				t.Fatalf("retry counter = %d, want 0", got)
			}
		})
	}
}

// A thief who presents the old token while the owner still holds an unused
// replacement gets a pair, but the owner's next refresh is then reuse, which ends
// the session for both.
func TestRefreshGraceTheftIsCaughtOnTheOwnersNextRefresh(t *testing.T) {
	for _, mode := range graceModes {
		t.Run(modeName(mode), func(t *testing.T) {
			_, k, _, _ := graceFixture(t, mode)
			rt1 := graceLogin(t, k, mode)
			owners := mustRefresh(t, k, rt1).RefreshToken
			thiefs := mustRefresh(t, k, rt1).RefreshToken

			if _, err := graceRefresh(k, owners); !errors.Is(err, authkit.ErrRefreshTokenReuse) {
				t.Fatalf("owner's refresh after a theft: want ErrRefreshTokenReuse, got %v", err)
			}
			if _, err := graceRefresh(k, thiefs); err == nil {
				t.Fatal("the thief's token must stop working once reuse is detected")
			}
		})
	}
}

// After the grace period the old token is reuse, whatever happened to its
// replacement.
func TestRefreshGraceExpires(t *testing.T) {
	for _, mode := range graceModes {
		t.Run(modeName(mode), func(t *testing.T) {
			db, k, _, userID := graceFixture(t, mode)
			rt1 := graceLogin(t, k, mode)
			mustRefresh(t, k, rt1)
			// Move the consumption of rt1 (the only consumed token) past the period.
			if _, err := db.Exec(`UPDATE authkit.refresh_tokens SET revoked_at = revoked_at - $1::interval
				WHERE user_id = $2 AND revoked_at IS NOT NULL`, (2 * gracePeriod).String(), userID); err != nil {
				t.Fatal(err)
			}
			if _, err := graceRefresh(k, rt1); !errors.Is(err, authkit.ErrRefreshTokenReuse) {
				t.Fatalf("old token after the grace period: want ErrRefreshTokenReuse, got %v", err)
			}
		})
	}
}

// Logging out ends the grace period: the replacement is revoked, so the old token
// cannot buy a new pair.
func TestRefreshGraceDoesNotSurviveLogout(t *testing.T) {
	for _, mode := range graceModes {
		t.Run(modeName(mode), func(t *testing.T) {
			ctx := context.Background()
			_, k, m, userID := graceFixture(t, mode)
			rt1 := graceLogin(t, k, mode)
			rt2 := mustRefresh(t, k, rt1).RefreshToken
			if err := k.AuthService().Logout(ctx, rt2); err != nil {
				t.Fatal(err)
			}
			if _, err := graceRefresh(k, rt1); err == nil {
				t.Fatal("old token after logout: want an error")
			}

			// Logging out every session deletes the tokens instead.
			rt1 = graceLogin(t, k, mode)
			mustRefresh(t, k, rt1)
			if err := k.AuthService().LogoutAll(ctx, userID); err != nil {
				t.Fatal(err)
			}
			if _, err := graceRefresh(k, rt1); err == nil {
				t.Fatal("old token after logging out everywhere: want an error")
			}
			if got := m.get(metrics.CounterRefreshRetry); got != 0 {
				t.Fatalf("retry counter = %d, want 0", got)
			}
		})
	}
}

// A retry into a workspace the user has left is refused without consuming
// anything: the unused replacement still works once the membership is back.
func TestRefreshGraceRetryChecksTheWorkspace(t *testing.T) {
	for _, mode := range graceModes {
		t.Run(modeName(mode), func(t *testing.T) {
			ctx := context.Background()
			_, k, _, userID := graceFixture(t, mode)
			rt1 := graceLogin(t, k, mode)
			rt2 := mustRefresh(t, k, rt1).RefreshToken

			if err := k.MembershipService().Remove(ctx, userID, graceTenant); err != nil {
				t.Fatal(err)
			}
			if _, err := graceRefresh(k, rt1); !errors.Is(err, authkit.ErrNoActiveMembership) {
				t.Fatalf("retry without a membership: want ErrNoActiveMembership, got %v", err)
			}
			if err := k.MembershipService().Add(ctx, model.AddMembershipRequest{UserID: userID, TenantID: graceTenant, Roles: []string{"Admin"}}); err != nil {
				t.Fatal(err)
			}
			mustRefresh(t, k, rt2)
		})
	}
}

// Two refreshes of the same token at once both succeed with a grace period (the
// second is a retry), and one token remains usable afterwards.
func TestRefreshGraceConcurrentRefresh(t *testing.T) {
	for _, mode := range graceModes {
		t.Run(modeName(mode), func(t *testing.T) {
			db, k, _, userID := graceFixture(t, mode)
			rt1 := graceLogin(t, k, mode)
			start := make(chan struct{})
			results := make(chan error, 2)
			for i := 0; i < 2; i++ {
				go func() {
					<-start
					_, err := graceRefresh(k, rt1)
					results <- err
				}()
			}
			close(start)
			if a, b := <-results, <-results; a != nil || b != nil {
				t.Fatalf("concurrent refreshes with a grace period: %v, %v", a, b)
			}
			var active int
			if err := db.QueryRow(`SELECT count(*) FROM authkit.refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`, userID).Scan(&active); err != nil {
				t.Fatal(err)
			}
			if active != 1 {
				t.Fatalf("%d refresh tokens are usable, want 1", active)
			}
		})
	}
}
