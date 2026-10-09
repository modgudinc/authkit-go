//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	authkit "github.com/modgudinc/authkit-go"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
)

// countingMetrics records counter increments as "name|label=value,..." keys.
type countingMetrics struct {
	mu     sync.Mutex
	counts map[string]int
}

func (m *countingMetrics) IncCounter(name string, labels ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.counts == nil {
		m.counts = map[string]int{}
	}
	key := name
	for i := 0; i+1 < len(labels); i += 2 {
		key += "|" + labels[i] + "=" + labels[i+1]
	}
	m.counts[key]++
}

func (m *countingMetrics) get(key string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counts[key]
}

func verifiedKit(t *testing.T, db *sql.DB, mode authkit.SessionMode, m metrics.Metrics, schemas ...string) *authkit.AuthKit {
	t.Helper()
	schema := ""
	if len(schemas) > 0 {
		schema = schemas[0]
	}
	namespace := ""
	if mode != authkit.SessionDisabled {
		namespace = "app"
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
		OTPConfig:      authkit.OTPConfig{HMACSecret: "integration-otp-hmac-secret-at-least-32-bytes"},
		SessionConfig:  authkit.SessionConfig{Mode: mode, Namespace: namespace, AbsoluteLifetime: 2 * time.Hour},
		Metrics:        m,
	})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// verifiedFixture builds the schema for mode (the session migrations only when
// session support is on, the external-identity migration always) and seeds
// admin@sessions.test, a password user with an Admin membership of sessions.test.
func verifiedFixture(t *testing.T, mode authkit.SessionMode) (*sql.DB, *authkit.AuthKit, *countingMetrics, string) {
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
	applyMigration(t, db, "000004_external_identities.up.sql")
	repo := repository.New(db, db)
	userID := createTenantAndUser(t, context.Background(), &repo, "sessions.test")
	m := &countingMetrics{}
	return db, verifiedKit(t, db, mode, m), m, userID
}

func modeName(mode authkit.SessionMode) string {
	return map[authkit.SessionMode]string{authkit.SessionDisabled: "disabled", authkit.SessionOptional: "optional", authkit.SessionRequired: "required"}[mode]
}

func openSession(t *testing.T, k *authkit.AuthKit, req model.OpenSessionRequest) *model.OpenSessionResponse {
	t.Helper()
	resp, err := k.VerifiedLoginService().OpenSession(context.Background(), req)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	return resp
}

func TestOpenSessionWithoutInstallationInEveryMode(t *testing.T) {
	for _, mode := range []authkit.SessionMode{authkit.SessionDisabled, authkit.SessionOptional, authkit.SessionRequired} {
		t.Run(modeName(mode), func(t *testing.T) {
			db, k, m, userID := verifiedFixture(t, mode)
			ctx := context.Background()
			resp := openSession(t, k, model.OpenSessionRequest{
				UserID: userID, SignInMethod: " Google ",
				SessionInfo: &model.SessionInfo{DeviceName: "Firefox"},
			})
			if resp.AccessToken == "" || resp.TenantID != "sessions.test" || len(resp.Memberships) != 1 || resp.User.ID != userID {
				t.Fatalf("single-workspace user should get a token: %+v", resp.LoginResponse)
			}
			if m.get(metrics.CounterVerifiedLogin+"|method=google") != 1 {
				t.Fatal("verified login not counted with its normalized method")
			}
			var lastLogin *time.Time
			if err := db.QueryRow("SELECT last_login FROM authkit.users WHERE id=$1", userID).Scan(&lastLogin); err != nil || lastLogin == nil {
				t.Fatalf("last_login not updated: %v", err)
			}
			claims, err := k.AuthService().ValidateJWT(ctx, resp.AccessToken)
			if err != nil {
				t.Fatal(err)
			}

			if mode == authkit.SessionDisabled {
				if resp.Session != nil || claims.SessionID != "" || strings.HasPrefix(resp.RefreshToken, "s1.") {
					t.Fatal("disabled mode must open a plain identity session")
				}
				_, err := k.VerifiedLoginService().OpenSession(ctx, model.OpenSessionRequest{
					UserID: userID, SignInMethod: "device_code", Installation: &model.InstallationBinding{InstallationID: "cli"},
				})
				requireError(t, err, authkit.ErrSessionDisabled)
			} else {
				if resp.Session == nil || resp.Session.InstallationID != "" || resp.Session.SignInMethod != "google" || claims.SessionID != resp.Session.ID {
					t.Fatalf("expected an installation-less session record: %+v", resp.Session)
				}
				stored, err := k.SessionService().Get(ctx, userID, resp.Session.ID)
				if err != nil || stored.SignInMethod != "google" || stored.InstallationID != "" {
					t.Fatalf("stored session: %+v, %v", stored, err)
				}
				// Not an installation binding, so device-only validation refuses it.
				_, err = k.InstallationAuthService().ValidateInstallationJWT(ctx, resp.AccessToken)
				requireError(t, err, authkit.ErrSessionRequired)
			}

			rotated, err := k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: resp.RefreshToken, TenantID: "sessions.test"})
			if err != nil {
				t.Fatal(err)
			}
			ws, err := k.AuthService().MintWorkspaceToken(ctx, rotated.RefreshToken, "sessions.test")
			if err != nil {
				t.Fatal(err)
			}
			wsClaims, err := k.AuthService().ValidateJWT(ctx, ws.AccessToken)
			if err != nil || wsClaims.SessionID != claims.SessionID {
				t.Fatalf("refresh or workspace switch lost the session: %v", err)
			}
			if mode == authkit.SessionDisabled {
				if err := k.AuthService().Logout(ctx, rotated.RefreshToken); err != nil {
					t.Fatal(err)
				}
				_, err = k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: rotated.RefreshToken, TenantID: "sessions.test"})
				if err == nil {
					t.Fatal("logout left the identity session usable")
				}
				return
			}
			if err := k.SessionService().Revoke(ctx, userID, resp.Session.ID); err != nil {
				t.Fatal(err)
			}
			_, err = k.AuthService().ValidateJWT(ctx, ws.AccessToken)
			requireError(t, err, authkit.ErrSessionRevoked)
			_, err = k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: rotated.RefreshToken, TenantID: "sessions.test"})
			requireError(t, err, authkit.ErrSessionRevoked)
		})
	}
}

func TestOpenSessionWithInstallation(t *testing.T) {
	for _, mode := range []authkit.SessionMode{authkit.SessionOptional, authkit.SessionRequired} {
		t.Run(modeName(mode), func(t *testing.T) {
			_, k, _, userID := verifiedFixture(t, mode)
			ctx := context.Background()
			browser := openSession(t, k, model.OpenSessionRequest{UserID: userID, SignInMethod: "github"})
			cli := openSession(t, k, model.OpenSessionRequest{
				UserID: userID, SignInMethod: "device_code",
				Installation: &model.InstallationBinding{InstallationID: "cli-1"},
			})
			bound, err := k.InstallationAuthService().ValidateInstallationJWT(ctx, cli.AccessToken)
			if err != nil {
				t.Fatal(err)
			}
			if bound.Session.InstallationID != "cli-1" || bound.Session.SignInMethod != "device_code" || bound.Session.ID != cli.Session.ID {
				t.Fatalf("binding: %+v", bound.Session)
			}
			password := sessionLogin(t, k, "mac")
			if password.Session.SignInMethod != model.SignInMethodPassword {
				t.Fatalf("password login recorded %q", password.Session.SignInMethod)
			}
			// Revoking the installation leaves the browser and the other installation alone.
			if err := k.SessionService().RevokeInstallation(ctx, userID, "cli-1"); err != nil {
				t.Fatal(err)
			}
			_, err = k.AuthService().ValidateJWT(ctx, cli.AccessToken)
			requireError(t, err, authkit.ErrSessionRevoked)
			for _, access := range []string{browser.AccessToken, password.AccessToken} {
				if _, err := k.AuthService().ValidateJWT(ctx, access); err != nil {
					t.Fatal(err)
				}
			}
			sessions, err := k.SessionService().List(ctx, userID, 10, 0)
			if err != nil || len(sessions) != 3 {
				t.Fatalf("list: %d, %v", len(sessions), err)
			}
			// Logout closes a verified session like any other.
			if err := k.AuthService().Logout(ctx, browser.RefreshToken); err != nil {
				t.Fatal(err)
			}
			_, err = k.AuthService().ValidateJWT(ctx, browser.AccessToken)
			requireError(t, err, authkit.ErrSessionRevoked)
			_, err = k.VerifiedLoginService().OpenSession(ctx, model.OpenSessionRequest{
				UserID: userID, SignInMethod: "device_code", Installation: &model.InstallationBinding{InstallationID: " padded"},
			})
			requireError(t, err, authkit.ErrInvalidInput)
		})
	}
}

func TestOpenSessionGates(t *testing.T) {
	db, k, _, userID := verifiedFixture(t, authkit.SessionRequired)
	ctx := context.Background()
	repo := repository.New(db, db)
	countSessions := func() int {
		var n int
		if err := db.QueryRow("SELECT count(*) FROM authkit.sessions").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	for _, method := range []string{"", "password", "PASSWORD", "sign in", "-google", strings.Repeat("x", 65)} {
		_, err := k.VerifiedLoginService().OpenSession(ctx, model.OpenSessionRequest{UserID: userID, SignInMethod: method})
		requireError(t, err, authkit.ErrInvalidInput)
	}
	_, err := k.VerifiedLoginService().OpenSession(ctx, model.OpenSessionRequest{SignInMethod: "google"})
	requireError(t, err, authkit.ErrInvalidInput)
	_, err = k.VerifiedLoginService().OpenSession(ctx, model.OpenSessionRequest{UserID: "01a11a39-0000-7000-8000-000000000000", SignInMethod: "google"})
	requireError(t, err, authkit.ErrNotFound)

	_, err = k.VerifiedLoginService().OpenSession(ctx, model.OpenSessionRequest{UserID: userID, SignInMethod: "google", TenantID: "elsewhere.test"})
	requireError(t, err, authkit.ErrNoActiveMembership)
	if countSessions() != 0 {
		t.Fatal("a refused workspace opened a session")
	}

	if err := k.UserService().Disable(ctx, userID); err != nil {
		t.Fatal(err)
	}
	_, err = k.VerifiedLoginService().OpenSession(ctx, model.OpenSessionRequest{UserID: userID, SignInMethod: "google"})
	requireError(t, err, authkit.ErrAccountDisabled)
	if err := k.UserService().Enable(ctx, userID); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Hour)
	if err := k.UserService().Lock(ctx, userID, &until); err != nil {
		t.Fatal(err)
	}
	_, err = k.VerifiedLoginService().OpenSession(ctx, model.OpenSessionRequest{UserID: userID, SignInMethod: "google"})
	requireError(t, err, authkit.ErrAccountLocked)
	if countSessions() != 0 {
		t.Fatal("a refused account opened a session")
	}
	// An expired lock does not block, as for password login.
	if _, err := db.Exec("UPDATE authkit.users SET locked_until=NOW()-INTERVAL '1 minute' WHERE id=$1", userID); err != nil {
		t.Fatal(err)
	}
	openSession(t, k, model.OpenSessionRequest{UserID: userID, SignInMethod: "google"})

	// Several workspaces and none chosen: a session but no access token yet.
	if err := repo.CreateTenant(ctx, model.CreateTenantRequest{TenantID: "second.test", Name: "second", AllowedDomains: []string{"sessions.test"}}); err != nil {
		t.Fatal(err)
	}
	grantMembership(t, ctx, &repo, userID, "second.test", []string{"Member"})
	resp := openSession(t, k, model.OpenSessionRequest{UserID: userID, SignInMethod: "email_link"})
	if resp.AccessToken != "" || resp.Session == nil || len(resp.Memberships) != 2 {
		t.Fatalf("expected workspace choice: %+v", resp.LoginResponse)
	}
	ws, err := k.AuthService().MintWorkspaceToken(ctx, resp.RefreshToken, "second.test")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := k.AuthService().ValidateJWT(ctx, ws.AccessToken)
	if err != nil || claims.TenantID != "second.test" || claims.SessionID != resp.Session.ID {
		t.Fatalf("workspace token: %v", err)
	}
	chosen := openSession(t, k, model.OpenSessionRequest{UserID: userID, SignInMethod: "email_link", TenantID: "second.test"})
	if chosen.TenantID != "second.test" || chosen.AccessToken == "" {
		t.Fatal("explicit workspace not selected")
	}

	// Account-wide actions revoke verified sessions like password ones.
	if err := k.AuthService().LogoutAll(ctx, userID); err != nil {
		t.Fatal(err)
	}
	_, err = k.AuthService().ValidateJWT(ctx, chosen.AccessToken)
	if err == nil {
		t.Fatal("logout-all left a verified session active")
	}
	record, err := k.SessionService().Get(ctx, userID, chosen.Session.ID)
	if err != nil || record.RevokedAt == nil {
		t.Fatalf("logout-all did not revoke the record: %v", err)
	}
}

func TestPasswordlessUser(t *testing.T) {
	db, k, m, _ := verifiedFixture(t, authkit.SessionRequired)
	ctx := context.Background()
	repo := repository.New(db, db)
	id, err := k.UserService().Create(ctx, model.CreateUserRequest{Email: "nopass@sessions.test", DisplayName: "No Pass"})
	if err != nil {
		t.Fatal(err)
	}
	grantMembership(t, ctx, &repo, id, "sessions.test", []string{"Member"})

	for _, guess := range []string{"", "ValidPass1!", "x", "another-guess", "1", "2", "3", "4", "5", "6"} {
		_, err := k.InstallationAuthService().LoginWithInstallation(ctx, model.InstallationLoginRequest{
			LoginRequest: model.LoginRequest{Email: "nopass@sessions.test", Password: guess, TenantID: "sessions.test"},
			Installation: model.InstallationBinding{InstallationID: "mac"},
		})
		requireError(t, err, authkit.ErrInvalidCredentials)
	}
	user, err := k.UserService().GetByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if user.HasPassword() || user.FailedLoginCount != 0 || user.IsLocked {
		t.Fatalf("password guesses counted against a passwordless user: %+v", user)
	}
	if m.get(metrics.CounterLoginFailure+"|reason=no_password") != 10 {
		t.Fatal("no_password failures not counted")
	}

	resp := openSession(t, k, model.OpenSessionRequest{UserID: id, SignInMethod: "otp"})
	if _, err := k.AuthService().ValidateJWT(ctx, resp.AccessToken); err != nil {
		t.Fatal(err)
	}
	err = k.AuthService().ChangePassword(ctx, model.ChangePasswordRequest{UserID: id, OldPassword: "", NewPassword: "ValidPass1!"})
	requireError(t, err, authkit.ErrIncorrectPassword)

	hash, err := k.PasswordService().HashPassword("FirstPass1!")
	if err != nil {
		t.Fatal(err)
	}
	if err := k.UserService().SetPassword(ctx, id, hash); err != nil {
		t.Fatal(err)
	}
	if _, err := k.InstallationAuthService().LoginWithInstallation(ctx, model.InstallationLoginRequest{
		LoginRequest: model.LoginRequest{Email: "nopass@sessions.test", Password: "FirstPass1!", TenantID: "sessions.test"},
		Installation: model.InstallationBinding{InstallationID: "mac"},
	}); err != nil {
		t.Fatalf("login after setting a first password: %v", err)
	}
	// Setting the password ended the verified session, as any credential change does.
	_, err = k.AuthService().ValidateJWT(ctx, resp.AccessToken)
	if err == nil {
		t.Fatal("setting a password left the earlier session active")
	}
}

func TestSessionSignInMigration(t *testing.T) {
	db := openTestDB(t)
	t.Cleanup(func() { applyMigration(t, db, "000001_identity_schema.down.sql"); _ = db.Close() })
	ctx := context.Background()
	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)
	applyMigration(t, db, "000002_installation_sessions.up.sql")
	repo := repository.New(db, db)
	userID := createTenantAndUser(t, ctx, &repo, "sessions.test")
	// A session as v0.20.2 wrote it, before the column existed.
	if _, err := db.Exec(`INSERT INTO authkit.sessions
		(id,user_id,namespace,installation_id,token_version,created_at,last_used_at,expires_at,absolute_expires_at)
		VALUES ('01a11a39-0000-7000-8000-000000000001',$1,'app','mac',0,NOW(),NOW(),NOW()+INTERVAL '1 hour',NOW()+INTERVAL '2 hours')`, userID); err != nil {
		t.Fatal(err)
	}
	applyMigration(t, db, "000003_session_sign_in.up.sql")
	applyMigration(t, db, "000003_session_sign_in.up.sql") // idempotent
	k := verifiedKit(t, db, authkit.SessionRequired, nil)
	old, err := k.SessionService().Get(ctx, userID, "01a11a39-0000-7000-8000-000000000001")
	if err != nil || old.SignInMethod != model.SignInMethodPassword {
		t.Fatalf("existing session should read as a password login: %+v, %v", old, err)
	}
	browser := openSession(t, k, model.OpenSessionRequest{UserID: userID, SignInMethod: "google"})

	applyMigration(t, db, "000003_session_sign_in.down.sql")
	var sessions, tokens int
	if err := db.QueryRow("SELECT count(*) FROM authkit.sessions").Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT count(*) FROM authkit.refresh_tokens WHERE family_id=$1", browser.Session.ID).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 || tokens != 0 {
		t.Fatalf("rollback must drop installation-less sessions and their tokens: %d sessions, %d tokens", sessions, tokens)
	}
	if _, err := db.Exec(`INSERT INTO authkit.sessions
		(id,user_id,namespace,installation_id,token_version,created_at,last_used_at,expires_at,absolute_expires_at)
		VALUES ('01a11a39-0000-7000-8000-000000000002',$1,'app','',0,NOW(),NOW(),NOW()+INTERVAL '1 hour',NOW()+INTERVAL '2 hours')`, userID); err == nil {
		t.Fatal("rollback did not restore the installation constraint")
	}
	applyMigration(t, db, "000003_session_sign_in.up.sql")
}

func TestVerifiedLoginCustomSchema(t *testing.T) {
	db := openTestDB(t)
	t.Cleanup(func() { _, _ = db.Exec("DROP SCHEMA IF EXISTS verified_custom CASCADE"); _ = db.Close() })
	applyCustomSchemaMigration(t, db, "verified_custom")
	for _, name := range []string{"000002_installation_sessions.up.sql", "000003_session_sign_in.up.sql", "000004_external_identities.up.sql"} {
		applyRenamedMigration(t, db, name, "verified_custom")
	}
	repo := repository.NewWithSchema(db, db, "verified_custom")
	userID := createTenantAndUser(t, context.Background(), &repo, "sessions.test")
	k := verifiedKit(t, db, authkit.SessionRequired, nil, "verified_custom")
	resp := openSession(t, k, model.OpenSessionRequest{UserID: userID, SignInMethod: "google"})
	if _, err := k.AuthService().ValidateJWT(context.Background(), resp.AccessToken); err != nil {
		t.Fatal(err)
	}
	linked, err := k.ExternalIdentityService().Link(context.Background(), model.LinkExternalIdentityRequest{UserID: userID, Provider: "google", Subject: "sub-1"})
	if err != nil || linked.UserID != userID {
		t.Fatalf("link in custom schema: %v", err)
	}
}

func applyRenamedMigration(t *testing.T, db *sql.DB, name, schema string) {
	t.Helper()
	sqlBytes, err := os.ReadFile(filepath.Join("..", "migrations", name)) //nolint:gosec // G304: test reads migration SQL from the repo's fixed migrations dir
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(strings.ReplaceAll(string(sqlBytes), "authkit.", schema+".")); err != nil {
		t.Fatalf("apply %s to %s: %v", name, schema, err)
	}
}
