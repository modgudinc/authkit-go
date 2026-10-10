//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

// Tests for the fixes of the readiness review: errors that name their cause, codes
// and hashes that stay out of errors and listings, rate-limit keys, the order of the
// account gates, last_login, locks the lockout must not shorten, and idempotent logout.

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	authkit "github.com/modgudinc/authkit-go"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/model"
)

// recordingLimiter allows everything and keeps the keys it was asked about.
type recordingLimiter struct {
	mu   sync.Mutex
	keys []string
}

func (l *recordingLimiter) Allow(_ context.Context, key string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys = append(l.keys, key)
	return true, nil
}

func (l *recordingLimiter) last(t *testing.T) string {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.keys) == 0 {
		t.Fatal("the limiter was never asked")
	}
	return l.keys[len(l.keys)-1]
}

// refusingLimiter refuses everything.
type refusingLimiter struct{}

func (refusingLimiter) Allow(context.Context, string) (bool, error) { return false, nil }

func readinessKit(t *testing.T, db *sql.DB, mode authkit.SessionMode, rl authkit.RateLimiter, m *countingMetrics) *authkit.AuthKit {
	t.Helper()
	cfg := authkit.Config{
		DBConnection: authkit.DatabaseConnection{IdentityRWDB: db, IdentityRODB: db},
		JWTConfig: authkit.JWTConfig{
			AccessSecret:           "integration-access-secret-at-least-32-bytes",
			RefreshTokenHMACSecret: "integration-refresh-hmac-secret-at-least-32b",
			AccessExpiry:           5 * time.Minute, RefreshExpiry: time.Hour,
		},
		APIKeyConfig:   authkit.APIKeyConfig{HMACSecret: "integration-api-hmac-secret-at-least-32-bytes"},
		PasswordConfig: authkit.PasswordConfig{BcryptCost: 4},
		SessionConfig:  authkit.SessionConfig{Mode: mode, Namespace: "desktop", AbsoluteLifetime: 2 * time.Hour},
		RateLimiter:    rl,
	}
	if m != nil {
		cfg.Metrics = m
	}
	k, err := authkit.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// readinessFixture is a fresh schema with the session migrations, a tenant
// "ready.test" and its admin, and a kit in mode with the given limiter and metrics.
func readinessFixture(t *testing.T, mode authkit.SessionMode, rl authkit.RateLimiter, m *countingMetrics) (*sql.DB, *repository.Repository, *authkit.AuthKit, string) {
	t.Helper()
	db := openTestDB(t)
	db.SetMaxOpenConns(12)
	t.Cleanup(func() { applyMigration(t, db, "000001_identity_schema.down.sql"); _ = db.Close() })
	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)
	applyMigration(t, db, "000002_installation_sessions.up.sql")
	applyMigration(t, db, "000003_session_sign_in.up.sql")
	repo := repository.New(db, db)
	userID := createTenantAndUser(t, context.Background(), &repo, "ready.test")
	return db, &repo, readinessKit(t, db, mode, rl, m), userID
}

func readinessLogin(t *testing.T, k *authkit.AuthKit, info *model.SessionInfo) *model.LoginResponse {
	t.Helper()
	resp, err := k.AuthService().Login(context.Background(), model.LoginRequest{
		Email: "admin@ready.test", Password: "ValidPass1!", TenantID: "ready.test", SessionInfo: info,
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestTenantCreateRefusesDuplicatesAndBlanks(t *testing.T) {
	ctx := context.Background()
	_, _, k, _ := readinessFixture(t, authkit.SessionDisabled, nil, nil)
	tenants := k.TenantService()

	_, err := tenants.Create(ctx, model.CreateTenantRequest{TenantID: "ready.test", Name: "Again", AllowedDomains: []string{"again.test"}})
	requireError(t, err, authkit.ErrTenantExists)
	if strings.Contains(err.Error(), "SQLSTATE") {
		t.Fatalf("raw driver error: %v", err)
	}

	for name, req := range map[string]model.CreateTenantRequest{
		"blank id":   {TenantID: "  ", Name: "Blank", AllowedDomains: []string{"blank.test"}},
		"blank name": {TenantID: "blank.test", Name: " ", AllowedDomains: []string{"blank.test"}},
		"no domains": {TenantID: "blank.test", Name: "Blank"},
		"bad domain": {TenantID: "blank.test", Name: "Blank", AllowedDomains: []string{"not a domain"}},
	} {
		_, err := tenants.Create(ctx, req)
		if !errors.Is(err, authkit.ErrInvalidInput) {
			t.Errorf("%s: err = %v, want ErrInvalidInput", name, err)
		}
	}

	err = tenants.ValidateDomainAccess(ctx, "someone@elsewhere.test", "ready.test")
	requireError(t, err, authkit.ErrInvalidInput)
	err = tenants.ValidateDomainAccess(ctx, "no-at-sign", "ready.test")
	requireError(t, err, authkit.ErrInvalidInput)
	if err := tenants.ValidateDomainAccess(ctx, "someone@ready.test", "ready.test"); err != nil {
		t.Fatalf("allowed domain: %v", err)
	}
}

func TestCreateWithUnknownTenantOrCreatorIsNotFound(t *testing.T) {
	ctx := context.Background()
	_, _, k, userID := readinessFixture(t, authkit.SessionDisabled, nil, nil)
	const ghost = "00000000-0000-4000-8000-000000000000"

	_, err := k.APIKeyService().Create(ctx, model.CreateAPIKeyRequest{TenantID: "nosuch.test", Name: "k", CreatedBy: userID})
	requireError(t, err, authkit.ErrNotFound)
	_, err = k.APIKeyService().Create(ctx, model.CreateAPIKeyRequest{TenantID: "ready.test", Name: "k", CreatedBy: ghost})
	requireError(t, err, authkit.ErrNotFound)

	_, err = k.InvitationService().Create(ctx, model.CreateInvitationRequest{TenantID: "nosuch.test", CreatedBy: userID, Email: "x@ready.test"})
	requireError(t, err, authkit.ErrNotFound)
	_, err = k.InvitationService().Create(ctx, model.CreateInvitationRequest{TenantID: "ready.test", CreatedBy: ghost, Email: "x@ready.test"})
	requireError(t, err, authkit.ErrNotFound)
}

func TestInvitationErrorsOmitTheCode(t *testing.T) {
	ctx := context.Background()
	_, _, k, _ := readinessFixture(t, authkit.SessionDisabled, nil, nil)
	const code = "SECRETINVITATIONCODE"
	for name, err := range map[string]error{
		"revoke": k.InvitationService().Revoke(ctx, code),
		"delete": k.InvitationService().Delete(ctx, code),
		"use":    k.InvitationService().IncrementUseCount(ctx, code),
	} {
		if err == nil {
			t.Fatalf("%s: no error for an unknown code", name)
		}
		if strings.Contains(err.Error(), code) {
			t.Errorf("%s: the error carries the code: %v", name, err)
		}
	}
}

func TestAPIKeyListingsOmitTheHash(t *testing.T) {
	ctx := context.Background()
	_, _, k, userID := readinessFixture(t, authkit.SessionDisabled, nil, nil)
	created, err := k.APIKeyService().Create(ctx, model.CreateAPIKeyRequest{TenantID: "ready.test", Name: "ci", CreatedBy: userID})
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.APIKeyService().Get(ctx, created.KeyID, "ready.test")
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyHash != "" {
		t.Error("Get returns the key hash")
	}
	list, err := k.APIKeyService().List(ctx, "ready.test", true)
	if err != nil || len(list) != 1 {
		t.Fatalf("List: %v, %d keys", err, len(list))
	}
	if list[0].KeyHash != "" {
		t.Error("List returns the key hash")
	}
	// The key still validates: the hash stayed in the database.
	if _, err := k.APIKeyService().Validate(ctx, created.APIKey); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestUserCreateRefusesBadEmails(t *testing.T) {
	ctx := context.Background()
	_, _, k, _ := readinessFixture(t, authkit.SessionDisabled, nil, nil)
	for _, email := range []string{"", "   ", "nope", "two@@ready.test", "space in@ready.test"} {
		_, err := k.UserService().Create(ctx, model.CreateUserRequest{Email: email, DisplayName: "X", PasswordHash: ""})
		if !errors.Is(err, authkit.ErrInvalidInput) {
			t.Errorf("%q: err = %v, want ErrInvalidInput", email, err)
		}
	}
}

func TestPasswordServiceVerifyReturnsSentinel(t *testing.T) {
	_, _, k, _ := readinessFixture(t, authkit.SessionDisabled, nil, nil)
	hash, err := k.PasswordService().HashPassword("ValidPass1!")
	if err != nil {
		t.Fatal(err)
	}
	requireError(t, k.PasswordService().VerifyPassword("WrongPass1!", hash), authkit.ErrIncorrectPassword)
	if err := k.PasswordService().VerifyPassword("ValidPass1!", hash); err != nil {
		t.Fatal(err)
	}
	if err := k.PasswordService().VerifyPassword("ValidPass1!", ""); err == nil || errors.Is(err, authkit.ErrIncorrectPassword) {
		t.Fatalf("a malformed hash is not a wrong password: %v", err)
	}
}

func TestUserListOrderIsStable(t *testing.T) {
	ctx := context.Background()
	db, _, k, _ := readinessFixture(t, authkit.SessionDisabled, nil, nil)
	for _, email := range []string{"a@ready.test", "b@ready.test", "c@ready.test"} {
		if _, err := k.UserService().Create(ctx, model.CreateUserRequest{Email: email, DisplayName: email}); err != nil {
			t.Fatal(err)
		}
	}
	// Bulk imports share a timestamp; paging must still visit every row once.
	if _, err := db.Exec("UPDATE authkit.users SET created_at = '2026-01-01T00:00:00Z'"); err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for offset := 0; offset < 4; offset++ {
		page, err := k.UserService().List(ctx, 1, offset)
		if err != nil || len(page) != 1 {
			t.Fatalf("page %d: %v, %d users", offset, err, len(page))
		}
		seen[page[0].ID]++
	}
	if len(seen) != 4 {
		t.Fatalf("paging visited %d distinct users of 4: %v", len(seen), seen)
	}
}

func TestValidateJWTReportsDisabledAndLocked(t *testing.T) {
	ctx := context.Background()
	_, _, k, userID := readinessFixture(t, authkit.SessionDisabled, nil, nil)
	users := k.UserService()

	resp := readinessLogin(t, k, nil)
	if err := users.Disable(ctx, userID); err != nil {
		t.Fatal(err)
	}
	// Disable also bumps token_version; the account state is the answer.
	_, err := k.AuthService().ValidateJWT(ctx, resp.AccessToken)
	requireError(t, err, authkit.ErrAccountDisabled)
	if err := users.Enable(ctx, userID); err != nil {
		t.Fatal(err)
	}
	// Re-enabled, the old token is still revoked by the version bump.
	_, err = k.AuthService().ValidateJWT(ctx, resp.AccessToken)
	requireError(t, err, authkit.ErrTokenRevoked)

	resp = readinessLogin(t, k, nil)
	if err := users.Lock(ctx, userID, nil); err != nil {
		t.Fatal(err)
	}
	_, err = k.AuthService().ValidateJWT(ctx, resp.AccessToken)
	requireError(t, err, authkit.ErrAccountLocked)
	if err := users.Unlock(ctx, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := k.AuthService().ValidateJWT(ctx, resp.AccessToken); err != nil {
		t.Fatalf("after unlock: %v", err)
	}
}

func TestSessionRevokeUnknownUserIsNotFound(t *testing.T) {
	ctx := context.Background()
	_, _, k, _ := readinessFixture(t, authkit.SessionRequired, nil, nil)
	const ghost = "00000000-0000-4000-8000-000000000000"
	err := k.SessionService().Revoke(ctx, ghost, "00000000-0000-4000-8000-000000000001")
	requireError(t, err, authkit.ErrNotFound)
	err = k.SessionService().RevokeInstallation(ctx, ghost, "laptop-1")
	requireError(t, err, authkit.ErrNotFound)
}

func TestRateLimitKeysAndLabels(t *testing.T) {
	ctx := context.Background()
	rl := &recordingLimiter{}
	m := &countingMetrics{}
	_, _, k, _ := readinessFixture(t, authkit.SessionDisabled, rl, m)

	readinessLogin(t, k, nil)
	if key := rl.last(t); key != "login:ready.test:email:admin@ready.test" {
		t.Errorf("login key without IP = %q", key)
	}
	resp := readinessLogin(t, k, &model.SessionInfo{IPAddress: "203.0.113.9"})
	if key := rl.last(t); key != "login:ready.test:203.0.113.9" {
		t.Errorf("login key with IP = %q", key)
	}

	// A refresh with no IP is keyed by the token's digest: never one shared bucket,
	// and never the token itself.
	refreshed, err := k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: resp.RefreshToken, TenantID: "ready.test"})
	if err != nil {
		t.Fatal(err)
	}
	key := rl.last(t)
	if !strings.HasPrefix(key, "refresh:token:") || len(key) != len("refresh:token:")+16 || strings.Contains(key, resp.RefreshToken) {
		t.Errorf("refresh key without IP = %q", key)
	}
	first := key
	refreshed, err = k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: refreshed.RefreshToken, TenantID: "ready.test"})
	if err != nil {
		t.Fatal(err)
	}
	if rl.last(t) == first {
		t.Error("two different tokens share a refresh key")
	}
	if _, err := k.AuthService().RefreshToken(ctx, model.RefreshRequest{
		RefreshToken: refreshed.RefreshToken, TenantID: "ready.test", SessionInfo: &model.SessionInfo{IPAddress: "203.0.113.9"},
	}); err != nil {
		t.Fatal(err)
	}
	if key := rl.last(t); key != "refresh:203.0.113.9" {
		t.Errorf("refresh key with IP = %q", key)
	}

	// A refusal counts under the operation, not the key: no email or IP in a label.
	_, _, refusing, _ := readinessFixture(t, authkit.SessionDisabled, refusingLimiter{}, m)
	_, err = refusing.AuthService().Login(ctx, model.LoginRequest{Email: "admin@ready.test", Password: "ValidPass1!", TenantID: "ready.test"})
	requireError(t, err, authkit.ErrRateLimited)
	if m.get("authkit_rate_limited_total|key=login") != 1 {
		t.Errorf("rate-limited counter labels: %v", m.counts)
	}
}

func TestLastLoginWaitsForASession(t *testing.T) {
	ctx := context.Background()
	_, repo, k, userID := readinessFixture(t, authkit.SessionDisabled, nil, nil)
	// A second tenant the admin is not a member of.
	if err := repo.CreateTenant(ctx, model.CreateTenantRequest{TenantID: "other.test", Name: "Other", AllowedDomains: []string{"other.test"}}); err != nil {
		t.Fatal(err)
	}
	// Two wrong passwords, then the right one into the wrong workspace.
	for range 2 {
		_, err := k.AuthService().Login(ctx, model.LoginRequest{Email: "admin@ready.test", Password: "WrongPass1!", TenantID: "ready.test"})
		requireError(t, err, authkit.ErrInvalidCredentials)
	}
	_, err := k.AuthService().Login(ctx, model.LoginRequest{Email: "admin@ready.test", Password: "ValidPass1!", TenantID: "other.test"})
	requireError(t, err, authkit.ErrNoActiveMembership)

	user, err := k.UserService().GetByID(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if user.LastLoginAt != nil {
		t.Error("last_login set by a login that opened no session")
	}
	if user.FailedLoginCount != 0 {
		t.Errorf("the right password did not reset the failed count: %d", user.FailedLoginCount)
	}

	readinessLogin(t, k, nil)
	user, err = k.UserService().GetByID(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if user.LastLoginAt == nil {
		t.Error("last_login not set by a login that opened a session")
	}
}

func TestFailedLoginsKeepALiveLock(t *testing.T) {
	ctx := context.Background()
	db, repo, k, userID := readinessFixture(t, authkit.SessionDisabled, nil, nil)
	lockedUntil := func() (bool, *time.Time) {
		var locked bool
		var until *time.Time
		if err := db.QueryRow("SELECT is_locked, locked_until FROM authkit.users WHERE id = $1", userID).Scan(&locked, &until); err != nil {
			t.Fatal(err)
		}
		return locked, until
	}

	// An indefinite admin lock survives the lockout threshold.
	if err := k.UserService().Lock(ctx, userID, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.RegisterFailedLogin(ctx, userID, 1, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	if locked, until := lockedUntil(); !locked || until != nil {
		t.Fatalf("indefinite lock after a failed login: locked=%v until=%v", locked, until)
	}

	// So does a lock that ends later than the lockout would.
	far := time.Now().Add(24 * time.Hour).Truncate(time.Microsecond)
	if err := k.UserService().Lock(ctx, userID, &far); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.RegisterFailedLogin(ctx, userID, 1, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	if locked, until := lockedUntil(); !locked || until == nil || !until.Equal(far) {
		t.Fatalf("long lock after a failed login: locked=%v until=%v", locked, until)
	}

	// A lock that has run out is replaced by the lockout.
	past := time.Now().Add(-time.Hour)
	if err := k.UserService().Lock(ctx, userID, &past); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.RegisterFailedLogin(ctx, userID, 1, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	if locked, until := lockedUntil(); !locked || until == nil || !until.After(time.Now()) {
		t.Fatalf("expired lock after a failed login: locked=%v until=%v", locked, until)
	}
}

func TestAutoUnlockIsAuditedAsSystem(t *testing.T) {
	ctx := context.Background()
	_, _, k, userID := readinessFixture(t, authkit.SessionDisabled, nil, nil)
	past := time.Now().Add(-time.Minute)
	if err := k.UserService().Lock(ctx, userID, &past); err != nil {
		t.Fatal(err)
	}
	readinessLogin(t, k, nil) // the expired lock is lifted on the way in
	history, err := k.UserService().StatusHistory(ctx, userID)
	if err != nil || len(history) < 2 {
		t.Fatalf("history: %v, %d rows", err, len(history))
	}
	if history[0].StatusType != "unlock" || history[0].ChangedByType != "system" {
		t.Errorf("auto-unlock audited as %s by %s", history[0].StatusType, history[0].ChangedByType)
	}
	if history[1].StatusType != "lock" || history[1].ChangedByType != "admin" {
		t.Errorf("admin lock audited as %s by %s", history[1].StatusType, history[1].ChangedByType)
	}
}

func TestLogoutAfterSessionCleanupSucceeds(t *testing.T) {
	ctx := context.Background()
	db, _, k, _ := readinessFixture(t, authkit.SessionRequired, nil, nil)
	resp, err := k.InstallationAuthService().LoginWithInstallation(ctx, model.InstallationLoginRequest{
		LoginRequest: model.LoginRequest{Email: "admin@ready.test", Password: "ValidPass1!", TenantID: "ready.test"},
		Installation: model.InstallationBinding{InstallationID: "laptop-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The session expires and the sweep removes it; the refresh row outlives it.
	if _, err := db.Exec("UPDATE authkit.sessions SET expires_at = created_at + interval '1 millisecond' WHERE id = $1", resp.Session.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := k.SessionService().CleanupExpired(ctx); err != nil || n != 1 {
		t.Fatalf("cleanup: %v, %d sessions", err, n)
	}
	if n := countRows(t, db, "SELECT count(*) FROM authkit.refresh_tokens"); n != 1 {
		t.Fatalf("refresh rows after cleanup: %d", n)
	}
	// Logging out of it is still a success: there is nothing left to revoke.
	if err := k.AuthService().Logout(ctx, resp.RefreshToken); err != nil {
		t.Fatalf("logout after cleanup: %v", err)
	}
	if err := k.AuthService().Logout(ctx, resp.RefreshToken); err != nil {
		t.Fatalf("second logout: %v", err)
	}
}
