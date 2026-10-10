//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	authkit "github.com/modgudinc/authkit-go"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/model"
)

// The public service methods that no other test reached, each checked against the
// database: what they change, what they return for a missing row, and that a
// missing row is ErrNotFound rather than an internal error.

func gapFixture(t *testing.T, tenantID string) (*sql.DB, *repository.Repository, *authkit.AuthKit, string) {
	t.Helper()
	db := openTestDB(t)
	t.Cleanup(func() { applyMigration(t, db, "000001_identity_schema.down.sql"); _ = db.Close() })
	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)
	repo := repository.New(db, db)
	return db, &repo, newIntegrationAuthKit(t, db), createTenantAndUser(t, context.Background(), &repo, tenantID)
}

// Get, List, HasPending, IncrementUseCount and Delete on invitations: the
// management calls around Create, Accept and ListActive.
func TestInvitationServiceManagement(t *testing.T) {
	ctx := context.Background()
	db, _, k, adminID := gapFixture(t, "invites.test")
	invites := k.InvitationService()

	_, err := invites.Get(ctx, "NOSUCHCODE0000000000")
	requireError(t, err, authkit.ErrNotFound)
	requireError(t, invites.Delete(ctx, "NOSUCHCODE0000000000"), authkit.ErrNotFound)
	requireError(t, invites.IncrementUseCount(ctx, "NOSUCHCODE0000000000"), authkit.ErrInvitationInvalid)

	two := 2
	first, err := invites.Create(ctx, model.CreateInvitationRequest{TenantID: "invites.test", CreatedBy: adminID, Email: "A@Invites.test", Roles: []string{"Member"}, MaxUses: &two})
	if err != nil {
		t.Fatal(err)
	}
	second, err := invites.Create(ctx, model.CreateInvitationRequest{TenantID: "invites.test", CreatedBy: adminID, Email: "b@invites.test", Roles: []string{"Admin", "Member"}})
	if err != nil {
		t.Fatal(err)
	}

	got, err := invites.Get(ctx, first.Code)
	if err != nil {
		t.Fatal(err)
	}
	if got.Email != "a@invites.test" || got.MaxUses != 2 || got.CurrentUses != 0 || got.TenantID != "invites.test" || got.CreatedBy != adminID || len(got.Roles) != 1 {
		t.Fatalf("Get: %+v", got)
	}
	if got.ExpiresAt.Sub(got.CreatedAt) < 6*24*time.Hour || got.ExpiresAt.Sub(got.CreatedAt) > 8*24*time.Hour {
		t.Fatalf("default lifetime is not seven days: created %v, expires %v", got.CreatedAt, got.ExpiresAt)
	}

	// List is newest first and scoped to the tenant.
	all, err := invites.List(ctx, "invites.test")
	if err != nil || len(all) != 2 || all[0].Code != second.Code || all[1].Code != first.Code {
		t.Fatalf("List: %v, %v", all, err)
	}
	if other, err := invites.List(ctx, "elsewhere.test"); err != nil || len(other) != 0 {
		t.Fatalf("List for another tenant: %v, %v", other, err)
	}

	// HasPending normalizes the email and is per tenant.
	for email, want := range map[string]bool{"a@invites.test": true, " A@INVITES.TEST ": true, "c@invites.test": false} {
		pending, err := invites.HasPending(ctx, email, "invites.test")
		if err != nil || pending != want {
			t.Fatalf("HasPending(%q) = %v, %v; want %v", email, pending, err, want)
		}
	}
	if pending, err := invites.HasPending(ctx, "a@invites.test", "elsewhere.test"); err != nil || pending {
		t.Fatalf("HasPending in another tenant = %v, %v", pending, err)
	}

	// IncrementUseCount stops at max_uses, and a used-up invitation is no longer
	// pending or active.
	for range 2 {
		if err := invites.IncrementUseCount(ctx, first.Code); err != nil {
			t.Fatal(err)
		}
	}
	requireError(t, invites.IncrementUseCount(ctx, first.Code), authkit.ErrInvitationInvalid)
	if got, _ := invites.Get(ctx, first.Code); got.CurrentUses != 2 {
		t.Fatalf("CurrentUses = %d after two increments and a refused third", got.CurrentUses)
	}
	if pending, _ := invites.HasPending(ctx, "a@invites.test", "invites.test"); pending {
		t.Fatal("a used-up invitation is still pending")
	}
	if ok, err := invites.Validate(ctx, first.Code); err != nil || ok {
		t.Fatalf("Validate(used up) = %v, %v", ok, err)
	}
	active, err := invites.ListActive(ctx, "invites.test")
	if err != nil || len(active) != 1 || active[0].Code != second.Code {
		t.Fatalf("ListActive: %v, %v", active, err)
	}

	// Delete removes exactly that invitation.
	if err := invites.Delete(ctx, first.Code); err != nil {
		t.Fatal(err)
	}
	_, err = invites.Get(ctx, first.Code)
	requireError(t, err, authkit.ErrNotFound)
	if n := countRows(t, db, "SELECT count(*) FROM authkit.invitations"); n != 1 {
		t.Fatalf("%d invitations left, want 1", n)
	}
}

// Delete revokes a pending OTP, and only that (email, purpose).
func TestOTPServiceDelete(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { applyMigration(t, db, "000001_identity_schema.down.sql"); _ = db.Close() })
	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)
	k, err := authkit.New(authkit.Config{
		DBConnection: authkit.DatabaseConnection{IdentityRWDB: db, IdentityRODB: db},
		JWTConfig: authkit.JWTConfig{
			AccessSecret:           "integration-access-secret-at-least-32-bytes",
			RefreshTokenHMACSecret: "integration-refresh-hmac-secret-at-least-32b",
		},
		APIKeyConfig: authkit.APIKeyConfig{HMACSecret: "integration-api-hmac-secret-at-least-32-bytes"},
		OTPConfig:    authkit.OTPConfig{HMACSecret: "integration-otp-hmac-secret-at-least-32-bytes"},
	})
	if err != nil {
		t.Fatal(err)
	}
	otp := k.OTPService()

	requireError(t, otp.Delete(ctx, "nobody@otp.test", "signup"), authkit.ErrNotFound)

	gen := func(purpose string) *model.GenerateResponse {
		t.Helper()
		resp, err := otp.Generate(ctx, model.OTPGenerateRequest{Email: "person@otp.test", Purpose: purpose, ExpirationDuration: 10 * time.Minute})
		if err != nil {
			t.Fatalf("Generate %s: %v", purpose, err)
		}
		return resp
	}
	signup := gen("signup")
	reset := gen("reset-password")

	// Normalizes the email like Generate does; deletes only that purpose.
	if err := otp.Delete(ctx, " Person@OTP.test ", "signup"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	requireError(t, otp.Validate(ctx, model.OTPValidateRequest{Email: "person@otp.test", Code: signup.Code, Purpose: "signup"}), authkit.ErrInvalidOTP)
	if err := otp.Validate(ctx, model.OTPValidateRequest{Email: "person@otp.test", Code: reset.Code, Purpose: "reset-password"}); err != nil {
		t.Fatalf("the other purpose's code was deleted too: %v", err)
	}
	requireError(t, otp.Delete(ctx, "person@otp.test", "signup"), authkit.ErrNotFound)
}

// UpdateLastLogin and IncrementFailedLoginCount write the columns the login path
// also writes, for applications that run their own checks.
func TestUserServiceActivityTracking(t *testing.T) {
	ctx := context.Background()
	db, _, k, userID := gapFixture(t, "activity.test")
	users := k.UserService()

	requireError(t, users.UpdateLastLogin(ctx, "00000000-0000-7000-8000-000000000000"), authkit.ErrNotFound)
	requireError(t, users.IncrementFailedLoginCount(ctx, "00000000-0000-7000-8000-000000000000"), authkit.ErrNotFound)

	before, err := users.GetByID(ctx, userID)
	if err != nil || before.LastLoginAt != nil || before.FailedLoginCount != 0 {
		t.Fatalf("fresh user: %+v, %v", before, err)
	}
	start := time.Now().Add(-time.Second)
	if err := users.UpdateLastLogin(ctx, userID); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := users.IncrementFailedLoginCount(ctx, userID); err != nil {
			t.Fatal(err)
		}
	}
	after, err := users.GetByID(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if after.LastLoginAt == nil || after.LastLoginAt.Before(start) {
		t.Fatalf("LastLoginAt = %v", after.LastLoginAt)
	}
	if after.FailedLoginCount != 3 || after.IsLocked {
		t.Fatalf("after three increments: count %d, locked %v", after.FailedLoginCount, after.IsLocked)
	}
	// The plain increment never locks; the login path's RegisterFailedLogin does.
	var lastFailed sql.NullTime
	if err := db.QueryRow("SELECT last_failed_login FROM authkit.users WHERE id=$1", userID).Scan(&lastFailed); err != nil {
		t.Fatal(err)
	}
	if !lastFailed.Valid || lastFailed.Time.Before(start) {
		t.Fatalf("last_failed_login = %v", lastFailed)
	}
	// Unlock resets the count the increments built up.
	if err := users.Unlock(ctx, userID); err != nil {
		t.Fatal(err)
	}
	if u, _ := users.GetByID(ctx, userID); u.FailedLoginCount != 0 {
		t.Fatalf("count %d after Unlock", u.FailedLoginCount)
	}
}

// UpdateSettings replaces the whole settings object and refuses what cannot be
// stored.
func TestTenantServiceUpdateSettings(t *testing.T) {
	ctx := context.Background()
	_, _, k, _ := gapFixture(t, "settings.test")
	tenants := k.TenantService()

	requireError(t, tenants.UpdateSettings(ctx, "nosuch.test", map[string]any{"a": 1}), authkit.ErrNotFound)
	requireError(t, tenants.UpdateSettings(ctx, "settings.test", map[string]any{"bad": math.Inf(1)}), authkit.ErrInvalidInput)
	requireError(t, tenants.UpdateSettings(ctx, "settings.test", map[string]any{"bad": make(chan int)}), authkit.ErrInvalidInput)
	requireError(t, tenants.UpdateSettings(ctx, "settings.test", map[string]any{"big": strings.Repeat("x", 1<<20)}), authkit.ErrValueTooLong)

	before, err := tenants.Get(ctx, "settings.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Settings) != 0 {
		t.Fatalf("settings before: %v", before.Settings)
	}

	if err := tenants.UpdateSettings(ctx, "settings.test", map[string]any{"theme": "dark", "limits": map[string]any{"seats": 5}, "beta": true}); err != nil {
		t.Fatal(err)
	}
	got, err := tenants.Get(ctx, "settings.test")
	if err != nil {
		t.Fatal(err)
	}
	limits, _ := got.Settings["limits"].(map[string]any)
	if got.Settings["theme"] != "dark" || got.Settings["beta"] != true || limits["seats"] != float64(5) {
		t.Fatalf("settings after: %v", got.Settings)
	}
	if !got.UpdatedAt.After(before.UpdatedAt) {
		t.Fatalf("updated_at did not move: %v -> %v", before.UpdatedAt, got.UpdatedAt)
	}

	// A replacement drops keys it does not name; nil and empty clear everything.
	if err := tenants.UpdateSettings(ctx, "settings.test", map[string]any{"theme": "light"}); err != nil {
		t.Fatal(err)
	}
	if got, _ = tenants.Get(ctx, "settings.test"); len(got.Settings) != 1 || got.Settings["theme"] != "light" {
		t.Fatalf("settings after replacement: %v", got.Settings)
	}
	if err := tenants.UpdateSettings(ctx, "settings.test", nil); err != nil {
		t.Fatal(err)
	}
	if got, _ = tenants.Get(ctx, "settings.test"); len(got.Settings) != 0 {
		t.Fatalf("settings after nil: %v", got.Settings)
	}
}

// Ping reports both handles; a closed one fails it.
func TestAuthKitPing(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	k := newIntegrationAuthKit(t, db)
	if err := k.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	closed := openTestDB(t)
	_ = closed.Close()
	k2, err := authkit.New(authkit.Config{
		DBConnection: authkit.DatabaseConnection{IdentityRWDB: db, IdentityRODB: closed},
		JWTConfig: authkit.JWTConfig{
			AccessSecret:           "integration-access-secret-at-least-32-bytes",
			RefreshTokenHMACSecret: "integration-refresh-hmac-secret-at-least-32b",
		},
		APIKeyConfig: authkit.APIKeyConfig{HMACSecret: "integration-api-hmac-secret-at-least-32-bytes"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := k2.Ping(ctx); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("Ping with a closed replica handle: %v", err)
	}
	// VerifyConnectivity makes New itself fail on the same condition.
	_, err = authkit.New(authkit.Config{
		DBConnection: authkit.DatabaseConnection{IdentityRWDB: closed, IdentityRODB: db},
		JWTConfig: authkit.JWTConfig{
			AccessSecret:           "integration-access-secret-at-least-32-bytes",
			RefreshTokenHMACSecret: "integration-refresh-hmac-secret-at-least-32b",
		},
		APIKeyConfig:       authkit.APIKeyConfig{HMACSecret: "integration-api-hmac-secret-at-least-32-bytes"},
		VerifyConnectivity: true,
	})
	if err == nil || !strings.Contains(err.Error(), "read-write") {
		t.Fatalf("New with VerifyConnectivity and a closed primary: %v", err)
	}
}

// A missing migration surfaces as ErrInternal from every service, never as a raw
// driver error.
func TestMissingTableIsInternalError(t *testing.T) {
	ctx := context.Background()
	db, _, k, userID := gapFixture(t, "notables.test")
	if _, err := db.Exec("DROP TABLE authkit.invitations"); err != nil {
		t.Fatal(err)
	}
	_, err := k.InvitationService().List(ctx, "notables.test")
	requireError(t, err, authkit.ErrInternal)
	if strings.Contains(err.Error(), "relation") || strings.Contains(err.Error(), "SQLSTATE") {
		t.Fatalf("error leaks the schema: %v", err)
	}
	_, err = k.InvitationService().Create(ctx, model.CreateInvitationRequest{TenantID: "notables.test", CreatedBy: userID, Email: "x@notables.test"})
	if !errors.Is(err, authkit.ErrInternal) {
		t.Fatalf("Create without the table: %v", err)
	}
}
