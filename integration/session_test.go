//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	authkit "github.com/modgudinc/authkit-go"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/model"
)

func sessionKit(t *testing.T, db *sql.DB, mode authkit.SessionMode, namespace string, schemas ...string) *authkit.AuthKit {
	t.Helper()
	schema := ""
	if len(schemas) > 0 {
		schema = schemas[0]
	}
	k, err := authkit.New(authkit.Config{
		DBConnection: authkit.DatabaseConnection{IdentityRWDB: db, IdentityRODB: db, IdentitySchema: schema},
		JWTConfig: authkit.JWTConfig{
			AccessSecret:           "integration-access-secret-at-least-32-bytes",
			RefreshTokenHMACSecret: "integration-refresh-hmac-secret-at-least-32b",
			AccessExpiry:           5 * time.Minute, RefreshExpiry: time.Hour,
		},
		APIKeyConfig:   authkit.APIKeyConfig{HMACSecret: "integration-api-hmac-secret-at-least-32-bytes"},
		PasswordConfig: authkit.PasswordConfig{BcryptCost: 4},
		SessionConfig:  authkit.SessionConfig{Mode: mode, Namespace: namespace, AbsoluteLifetime: 2 * time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sessionFixture(t *testing.T, mode authkit.SessionMode, migrate bool) (*sql.DB, *authkit.AuthKit, string) {
	t.Helper()
	db := openTestDB(t)
	db.SetMaxOpenConns(12)
	t.Cleanup(func() { applyMigration(t, db, "000001_identity_schema.down.sql"); _ = db.Close() })
	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")
	if migrate {
		applyMigration(t, db, "000002_installation_sessions.up.sql")
		applyMigration(t, db, "000003_session_sign_in.up.sql")
	}
	repo := repository.New(db, db)
	userID := createTenantAndUser(t, context.Background(), &repo, "sessions.test")
	return db, sessionKit(t, db, mode, "hugin"), userID
}

func sessionLogin(t *testing.T, k *authkit.AuthKit, installation string) *model.InstallationLoginResponse {
	t.Helper()
	resp, err := k.InstallationAuthService().LoginWithInstallation(context.Background(), model.InstallationLoginRequest{
		LoginRequest: model.LoginRequest{Email: "admin@sessions.test", Password: "ValidPass1!", TenantID: "sessions.test"},
		Installation: model.InstallationBinding{InstallationID: installation},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Session == nil || resp.Session.ID == "" || resp.Session.InstallationID != installation {
		t.Fatal("missing installation session")
	}
	return resp
}

func requireError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestSessionDisabledOldSchema(t *testing.T) {
	db, k, userID := sessionFixture(t, authkit.SessionDisabled, false)
	ctx := context.Background()
	resp, err := k.AuthService().Login(ctx, model.LoginRequest{Email: "admin@sessions.test", Password: "ValidPass1!", TenantID: "sessions.test"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(resp.AccessToken, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "\"sid\"") {
		t.Fatal("legacy token shape changed")
	}
	if _, err := k.AuthService().ValidateJWT(ctx, resp.AccessToken); err != nil {
		t.Fatal(err)
	}
	rotated, err := k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: resp.RefreshToken, TenantID: "sessions.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.AuthService().MintWorkspaceToken(ctx, rotated.RefreshToken, "sessions.test"); err != nil {
		t.Fatal(err)
	}
	if err := k.AuthService().Logout(ctx, rotated.RefreshToken); err != nil {
		t.Fatal(err)
	}
	_, err = k.SessionService().List(ctx, userID, 10, 0)
	requireError(t, err, authkit.ErrSessionDisabled)
	_, err = k.InstallationAuthService().LoginWithInstallation(ctx, model.InstallationLoginRequest{})
	requireError(t, err, authkit.ErrSessionDisabled)
	// The new table truly does not exist.
	var table *string
	if err := db.QueryRow("SELECT to_regclass('authkit.sessions')::text").Scan(&table); err != nil {
		t.Fatal(err)
	}
	if table != nil {
		t.Fatal("disabled fixture unexpectedly has sessions table")
	}
}

func TestInstallationSessionLifecycle(t *testing.T) {
	for _, mode := range []authkit.SessionMode{authkit.SessionOptional, authkit.SessionRequired} {
		t.Run(map[authkit.SessionMode]string{authkit.SessionOptional: "optional", authkit.SessionRequired: "required"}[mode], func(t *testing.T) {
			db, k, userID := sessionFixture(t, mode, true)
			ctx := context.Background()
			mac := sessionLogin(t, k, "mac")
			phone := sessionLogin(t, k, "iphone")
			first, err := k.InstallationAuthService().ValidateInstallationJWT(ctx, mac.AccessToken)
			if err != nil {
				t.Fatal(err)
			}
			if first.Session.ID != mac.Session.ID || first.Claims.SessionID != mac.Session.ID {
				t.Fatal("sid binding mismatch")
			}
			if first.Claims.ExpiresAt.After(mac.Session.ExpiresAt) {
				t.Fatal("access token exceeds session lifetime")
			}
			rotated, err := k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: mac.RefreshToken, TenantID: "sessions.test"})
			if err != nil {
				t.Fatal(err)
			}
			if rotated.RefreshToken == mac.RefreshToken {
				t.Fatal("refresh did not rotate")
			}
			after, err := k.InstallationAuthService().ValidateInstallationJWT(ctx, rotated.AccessToken)
			if err != nil {
				t.Fatal(err)
			}
			if after.Session.ID != mac.Session.ID || after.Claims.ID == first.Claims.ID {
				t.Fatal("rotation changed sid or reused jti")
			}
			if _, err := k.AuthService().ValidateJWT(ctx, mac.AccessToken); err != nil {
				t.Fatalf("normal rotation revoked old access: %v", err)
			}
			ws, err := k.AuthService().MintWorkspaceToken(ctx, rotated.RefreshToken, "sessions.test")
			if err != nil {
				t.Fatal(err)
			}
			wc, err := k.AuthService().ValidateJWT(ctx, ws.AccessToken)
			if err != nil || wc.SessionID != mac.Session.ID {
				t.Fatalf("workspace mint lost binding: %v", err)
			}
			if err := k.SessionService().Revoke(ctx, userID, mac.Session.ID); err != nil {
				t.Fatal(err)
			}
			if err := k.SessionService().Revoke(ctx, userID, mac.Session.ID); err != nil {
				t.Fatal(err)
			}
			_, err = k.AuthService().ValidateJWT(ctx, rotated.AccessToken)
			requireError(t, err, authkit.ErrSessionRevoked)
			_, err = k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: rotated.RefreshToken, TenantID: "sessions.test"})
			requireError(t, err, authkit.ErrSessionRevoked)
			_, err = k.AuthService().MintWorkspaceToken(ctx, rotated.RefreshToken, "sessions.test")
			requireError(t, err, authkit.ErrSessionRevoked)
			// A consumed token on an intentionally revoked session must not trigger
			// identity-wide reuse invalidation.
			_, err = k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: mac.RefreshToken, TenantID: "sessions.test"})
			requireError(t, err, authkit.ErrSessionRevoked)
			if _, err := k.AuthService().ValidateJWT(ctx, phone.AccessToken); err != nil {
				t.Fatalf("unrelated phone invalidated: %v", err)
			}
			secondPhone := sessionLogin(t, k, "iphone")
			otherApp := sessionKit(t, db, mode, "another-app")
			otherLogin := sessionLogin(t, otherApp, "iphone")
			if err := k.SessionService().RevokeInstallation(ctx, userID, "iphone"); err != nil {
				t.Fatal(err)
			}
			for _, access := range []string{phone.AccessToken, secondPhone.AccessToken} {
				_, err := k.AuthService().ValidateJWT(ctx, access)
				requireError(t, err, authkit.ErrSessionRevoked)
			}
			if _, err := otherApp.AuthService().ValidateJWT(ctx, otherLogin.AccessToken); err != nil {
				t.Fatalf("cross-app revoke: %v", err)
			}
			sessions, err := k.SessionService().List(ctx, userID, 10, 0)
			if err != nil || len(sessions) != 3 {
				t.Fatalf("scoped list: %d, %v", len(sessions), err)
			}
		})
	}
}

func TestSessionModesAndNoDowngrade(t *testing.T) {
	db, optional, userID := sessionFixture(t, authkit.SessionOptional, true)
	ctx := context.Background()
	legacy := sessionKit(t, db, authkit.SessionDisabled, "")
	required := sessionKit(t, db, authkit.SessionRequired, "hugin")
	old, err := legacy.AuthService().Login(ctx, model.LoginRequest{Email: "admin@sessions.test", Password: "ValidPass1!", TenantID: "sessions.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := optional.AuthService().ValidateJWT(ctx, old.AccessToken); err != nil {
		t.Fatal(err)
	}
	if _, err := optional.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: old.RefreshToken, TenantID: "sessions.test"}); err != nil {
		t.Fatal(err)
	}
	_, err = required.AuthService().ValidateJWT(ctx, old.AccessToken)
	requireError(t, err, authkit.ErrSessionRequired)
	_, err = required.TokenService().ValidateRefreshToken(ctx, old.RefreshToken)
	requireError(t, err, authkit.ErrSessionRequired)
	_, err = required.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: old.RefreshToken, TenantID: "sessions.test"})
	requireError(t, err, authkit.ErrSessionRequired)
	_, err = required.AuthService().MintWorkspaceToken(ctx, old.RefreshToken, "sessions.test")
	requireError(t, err, authkit.ErrSessionRequired)
	_, err = required.AuthService().Login(ctx, model.LoginRequest{})
	requireError(t, err, authkit.ErrSessionRequired)
	_, err = required.AuthService().LoginByEmail(ctx, model.LoginByEmailRequest{})
	requireError(t, err, authkit.ErrSessionRequired)
	_, err = required.JWTService().GenerateAccessToken(&model.User{}, &model.Membership{})
	requireError(t, err, authkit.ErrSessionRequired)
	_, err = required.TokenService().GenerateTokenPair(ctx, &model.User{}, &model.Membership{}, nil)
	requireError(t, err, authkit.ErrSessionRequired)
	bound := sessionLogin(t, optional, "mac")
	_, err = legacy.AuthService().ValidateJWT(ctx, bound.AccessToken)
	requireError(t, err, authkit.ErrSessionDisabled)
	_, err = legacy.TokenService().ValidateRefreshToken(ctx, bound.RefreshToken)
	requireError(t, err, authkit.ErrSessionDisabled)
	_, err = legacy.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: bound.RefreshToken, TenantID: "sessions.test"})
	requireError(t, err, authkit.ErrSessionDisabled)
	// Missing session data cannot turn a marked bound credential into legacy.
	if _, err := db.Exec("DELETE FROM authkit.sessions WHERE id=$1", bound.Session.ID); err != nil {
		t.Fatal(err)
	}
	_, err = optional.AuthService().ValidateJWT(ctx, bound.AccessToken)
	requireError(t, err, authkit.ErrSessionRevoked)
	_, err = optional.TokenService().ValidateRefreshToken(ctx, bound.RefreshToken)
	requireError(t, err, authkit.ErrSessionRevoked)
	_, err = optional.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: bound.RefreshToken, TenantID: "sessions.test"})
	requireError(t, err, authkit.ErrSessionRevoked)
	_, err = optional.SessionService().Get(ctx, userID, bound.Session.ID)
	requireError(t, err, authkit.ErrNotFound)
}

func TestSessionWorkspaceSelectionAndLogout(t *testing.T) {
	db, k, userID := sessionFixture(t, authkit.SessionRequired, true)
	ctx := context.Background()
	repo := repository.New(db, db)
	if err := repo.CreateTenant(ctx, model.CreateTenantRequest{TenantID: "second.test", Name: "second", AllowedDomains: []string{"sessions.test"}}); err != nil {
		t.Fatal(err)
	}
	grantMembership(t, ctx, &repo, userID, "second.test", []string{"Member"})
	login, err := k.InstallationAuthService().LoginByEmailWithInstallation(ctx, model.InstallationLoginByEmailRequest{
		LoginByEmailRequest: model.LoginByEmailRequest{Email: "admin@sessions.test", Password: "ValidPass1!"},
		Installation:        model.InstallationBinding{InstallationID: "mac"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if login.AccessToken != "" || login.Session == nil {
		t.Fatal("multiple workspaces must return a bound identity session without selection")
	}
	ws, err := k.AuthService().MintWorkspaceToken(ctx, login.RefreshToken, "second.test")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := k.AuthService().ValidateJWT(ctx, ws.AccessToken)
	if err != nil || claims.SessionID != login.Session.ID || claims.TenantID != "second.test" {
		t.Fatalf("workspace binding: %v", err)
	}
	_, err = k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: login.RefreshToken, TenantID: "absent"})
	requireError(t, err, authkit.ErrNoActiveMembership)
	// A rejected workspace must not consume the refresh token.
	rotated, err := k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: login.RefreshToken, TenantID: "sessions.test"})
	if err != nil {
		t.Fatal(err)
	}
	other := sessionLogin(t, k, "iphone")
	if err := k.AuthService().Logout(ctx, rotated.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if err := k.AuthService().Logout(ctx, rotated.RefreshToken); err != nil {
		t.Fatal(err)
	}
	_, err = k.AuthService().ValidateJWT(ctx, ws.AccessToken)
	requireError(t, err, authkit.ErrSessionRevoked)
	_, err = k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: rotated.RefreshToken, TenantID: "sessions.test"})
	requireError(t, err, authkit.ErrSessionRevoked)
	if _, err := k.AuthService().ValidateJWT(ctx, other.AccessToken); err != nil {
		t.Fatal(err)
	}
}

func TestSessionOwnershipAndExpiry(t *testing.T) {
	db, k, userID := sessionFixture(t, authkit.SessionRequired, true)
	ctx := context.Background()
	login := sessionLogin(t, k, "mac")
	repo := repository.New(db, db)
	otherID := createTenantAndUser(t, ctx, &repo, "other.test")
	_, err := k.SessionService().Get(ctx, otherID, login.Session.ID)
	requireError(t, err, authkit.ErrNotFound)
	requireError(t, k.SessionService().Revoke(ctx, otherID, login.Session.ID), authkit.ErrNotFound)
	if err := k.SessionService().RevokeInstallation(ctx, otherID, "mac"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.AuthService().ValidateJWT(ctx, login.AccessToken); err != nil {
		t.Fatal(err)
	}
	otherApp := sessionKit(t, db, authkit.SessionRequired, "other")
	_, err = otherApp.AuthService().ValidateJWT(ctx, login.AccessToken)
	requireError(t, err, authkit.ErrSessionRevoked)
	_, err = otherApp.TokenService().ValidateRefreshToken(ctx, login.RefreshToken)
	requireError(t, err, authkit.ErrSessionRevoked)
	requireError(t, otherApp.SessionService().Revoke(ctx, userID, login.Session.ID), authkit.ErrNotFound)
	// Correctly signed claims still need a matching session owner.
	claims, err := k.JWTService().ValidateAccessToken(login.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	claims.UserID = otherID
	claims.Subject = otherID
	claims.TenantID = "other.test"
	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("integration-access-secret-at-least-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = k.AuthService().ValidateJWT(ctx, forged)
	requireError(t, err, authkit.ErrSessionRevoked)
	// Backdate the record, preserving the schema's lifetime invariant.
	if _, err := db.Exec("UPDATE authkit.sessions SET created_at=NOW()-INTERVAL '2 hours', expires_at=NOW()-INTERVAL '1 second' WHERE id=$1", login.Session.ID); err != nil {
		t.Fatal(err)
	}
	_, err = k.AuthService().ValidateJWT(ctx, login.AccessToken)
	requireError(t, err, authkit.ErrSessionRevoked)
	_, err = k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: login.RefreshToken, TenantID: "sessions.test"})
	requireError(t, err, authkit.ErrSessionRevoked)
	n, err := k.SessionService().CleanupExpired(ctx)
	if err != nil || n != 1 {
		t.Fatalf("cleanup: %d, %v", n, err)
	}
	_, err = k.TokenService().ValidateRefreshToken(ctx, login.RefreshToken)
	requireError(t, err, authkit.ErrSessionRevoked)
}

func TestSessionConcurrentRefreshAndRevoke(t *testing.T) {
	_, k, userID := sessionFixture(t, authkit.SessionRequired, true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	phone := sessionLogin(t, k, "iphone")
	for i := 0; i < 20; i++ {
		login := sessionLogin(t, k, "mac")
		start := make(chan struct{})
		type result struct {
			response *model.RefreshResponse
			err      error
		}
		refreshDone := make(chan result, 1)
		revokeDone := make(chan error, 1)
		go func() {
			<-start
			resp, err := k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: login.RefreshToken, TenantID: "sessions.test"})
			refreshDone <- result{resp, err}
		}()
		go func() { <-start; revokeDone <- k.SessionService().Revoke(ctx, userID, login.Session.ID) }()
		close(start)
		r := <-refreshDone
		if err := <-revokeDone; err != nil {
			t.Fatal(err)
		}
		if r.err != nil && !errors.Is(r.err, authkit.ErrSessionRevoked) {
			t.Fatal(r.err)
		}
		_, err := k.AuthService().ValidateJWT(ctx, login.AccessToken)
		requireError(t, err, authkit.ErrSessionRevoked)
		if r.response != nil {
			_, err := k.AuthService().ValidateJWT(ctx, r.response.AccessToken)
			requireError(t, err, authkit.ErrSessionRevoked)
			_, err = k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: r.response.RefreshToken, TenantID: "sessions.test"})
			requireError(t, err, authkit.ErrSessionRevoked)
		}
	}
	if _, err := k.AuthService().ValidateJWT(ctx, phone.AccessToken); err != nil {
		t.Fatal(err)
	}
}

func TestSessionConcurrentRefreshReuse(t *testing.T) {
	db, k, userID := sessionFixture(t, authkit.SessionRequired, true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	login := sessionLogin(t, k, "mac")
	phone := sessionLogin(t, k, "iphone")
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			_, err := k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: login.RefreshToken, TenantID: "sessions.test"})
			results <- err
		}()
	}
	close(start)
	a, b := <-results, <-results
	winnerAndReuse := (a == nil && errors.Is(b, authkit.ErrRefreshTokenReuse)) || (b == nil && errors.Is(a, authkit.ErrRefreshTokenReuse))
	if !winnerAndReuse {
		t.Fatalf("expected one winner and one detected reuse: %v, %v", a, b)
	}
	_, err := k.AuthService().ValidateJWT(ctx, phone.AccessToken)
	requireError(t, err, authkit.ErrTokenRevoked)
	var before, after int
	if err := db.QueryRow("SELECT token_version FROM authkit.users WHERE id=$1", userID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	_, err = k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: login.RefreshToken, TenantID: "sessions.test"})
	requireError(t, err, authkit.ErrSessionRevoked)
	if err := db.QueryRow("SELECT token_version FROM authkit.users WHERE id=$1", userID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatal("retry after revoked session bumped identity again")
	}
}

func TestSessionMigrationAndDatabaseFailure(t *testing.T) {
	db, k, _ := sessionFixture(t, authkit.SessionRequired, true)
	ctx := context.Background()
	login := sessionLogin(t, k, "mac")
	applyMigration(t, db, "000002_installation_sessions.down.sql")
	_, err := k.AuthService().ValidateJWT(ctx, login.AccessToken)
	requireError(t, err, authkit.ErrInternal)
	_, err = k.TokenService().ValidateRefreshToken(ctx, login.RefreshToken)
	requireError(t, err, authkit.ErrInternal)
	// Rolling back the additive table did not remove identity data.
	disabled := sessionKit(t, db, authkit.SessionDisabled, "")
	if _, err := disabled.AuthService().Login(ctx, model.LoginRequest{Email: "admin@sessions.test", Password: "ValidPass1!", TenantID: "sessions.test"}); err != nil {
		t.Fatal(err)
	}
	_, err = disabled.AuthService().ValidateJWT(ctx, login.AccessToken)
	requireError(t, err, authkit.ErrSessionDisabled)
}

func TestSessionAccountAndMembershipRevocation(t *testing.T) {
	for _, action := range []string{"logout-all", "disable", "lock", "password"} {
		t.Run(action, func(t *testing.T) {
			_, k, userID := sessionFixture(t, authkit.SessionRequired, true)
			ctx := context.Background()
			mac := sessionLogin(t, k, "mac")
			phone := sessionLogin(t, k, "iphone")
			var err error
			switch action {
			case "logout-all":
				err = k.AuthService().LogoutAll(ctx, userID)
			case "disable":
				err = k.UserService().Disable(ctx, userID)
				if err == nil {
					err = k.UserService().Enable(ctx, userID)
				}
			case "lock":
				err = k.UserService().Lock(ctx, userID, nil)
				if err == nil {
					err = k.UserService().Unlock(ctx, userID)
				}
			case "password":
				err = k.AuthService().ChangePassword(ctx, model.ChangePasswordRequest{UserID: userID, OldPassword: "ValidPass1!", NewPassword: "DifferentPass2!"})
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, login := range []*model.InstallationLoginResponse{mac, phone} {
				if _, err := k.AuthService().ValidateJWT(ctx, login.AccessToken); err == nil {
					t.Fatal("account action left access active")
				}
				if _, err := k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: login.RefreshToken, TenantID: "sessions.test"}); err == nil {
					t.Fatal("account action left refresh active")
				}
				record, err := k.SessionService().Get(ctx, userID, login.Session.ID)
				if err != nil || record.RevokedAt == nil {
					t.Fatalf("account action did not revoke record: %v", err)
				}
			}
		})
	}
	t.Run("membership", func(t *testing.T) {
		db, k, userID := sessionFixture(t, authkit.SessionRequired, true)
		ctx := context.Background()
		repo := repository.New(db, db)
		if err := repo.CreateTenant(ctx, model.CreateTenantRequest{TenantID: "second.test", Name: "second", AllowedDomains: []string{"sessions.test"}}); err != nil {
			t.Fatal(err)
		}
		grantMembership(t, ctx, &repo, userID, "second.test", []string{"Member"})
		login := sessionLogin(t, k, "mac")
		second, err := k.AuthService().MintWorkspaceToken(ctx, login.RefreshToken, "second.test")
		if err != nil {
			t.Fatal(err)
		}
		if err := k.MembershipService().Remove(ctx, userID, "sessions.test"); err != nil {
			t.Fatal(err)
		}
		_, err = k.AuthService().ValidateJWT(ctx, login.AccessToken)
		requireError(t, err, authkit.ErrTokenRevoked)
		if _, err := k.AuthService().ValidateJWT(ctx, second.AccessToken); err != nil {
			t.Fatal(err)
		}
		_, err = k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: login.RefreshToken, TenantID: "sessions.test"})
		requireError(t, err, authkit.ErrNoActiveMembership)
		if _, err := k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: login.RefreshToken, TenantID: "second.test"}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSessionIssuanceAtomicityAndAbsoluteCap(t *testing.T) {
	db, k, _ := sessionFixture(t, authkit.SessionRequired, true)
	ctx := context.Background()
	if _, err := db.Exec("ALTER TABLE authkit.refresh_tokens ADD CONSTRAINT reject_test_insert CHECK (token_hash='never')"); err != nil {
		t.Fatal(err)
	}
	_, err := k.InstallationAuthService().LoginWithInstallation(ctx, model.InstallationLoginRequest{
		LoginRequest: model.LoginRequest{Email: "admin@sessions.test", Password: "ValidPass1!", TenantID: "sessions.test"},
		Installation: model.InstallationBinding{InstallationID: "mac"},
	})
	requireError(t, err, authkit.ErrInternal)
	var count int
	if err := db.QueryRow("SELECT count(*) FROM authkit.sessions").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed token creation left an orphan session")
	}
	if _, err := db.Exec("ALTER TABLE authkit.refresh_tokens DROP CONSTRAINT reject_test_insert"); err != nil {
		t.Fatal(err)
	}
	login, err := k.InstallationAuthService().LoginByEmailWithInstallation(ctx, model.InstallationLoginByEmailRequest{
		LoginByEmailRequest: model.LoginByEmailRequest{Email: "admin@sessions.test", Password: "ValidPass1!"},
		Installation:        model.InstallationBinding{InstallationID: "mac"},
	})
	if err != nil || login.AccessToken == "" {
		t.Fatalf("single-workspace bound login: %v", err)
	}
	capTime := time.Now().Add(30 * time.Second).Truncate(time.Second)
	if _, err := db.Exec("UPDATE authkit.sessions SET expires_at=$1,absolute_expires_at=$1 WHERE id=$2", capTime, login.Session.ID); err != nil {
		t.Fatal(err)
	}
	rotated, err := k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: login.RefreshToken, TenantID: "sessions.test"})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := k.InstallationAuthService().ValidateInstallationJWT(ctx, rotated.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Claims.ExpiresAt.After(capTime) || binding.Session.ExpiresAt.After(capTime) {
		t.Fatal("refresh extended absolute lifetime")
	}
}

func TestSessionCustomSchema(t *testing.T) {
	db := openTestDB(t)
	t.Cleanup(func() { _, _ = db.Exec("DROP SCHEMA IF EXISTS session_custom CASCADE"); _ = db.Close() })
	applyCustomSchemaMigration(t, db, "session_custom")
	applyRenamedMigration(t, db, "000002_installation_sessions.up.sql", "session_custom")
	applyRenamedMigration(t, db, "000003_session_sign_in.up.sql", "session_custom")
	repo := repository.NewWithSchema(db, db, "session_custom")
	userID := createTenantAndUser(t, context.Background(), &repo, "sessions.test")
	k := sessionKit(t, db, authkit.SessionRequired, "hugin", "session_custom")
	login := sessionLogin(t, k, "mac")
	if _, err := k.AuthService().ValidateJWT(context.Background(), login.AccessToken); err != nil {
		t.Fatal(err)
	}
	if err := k.SessionService().Revoke(context.Background(), userID, login.Session.ID); err != nil {
		t.Fatal(err)
	}
	_, err := k.AuthService().ValidateJWT(context.Background(), login.AccessToken)
	requireError(t, err, authkit.ErrSessionRevoked)
}
