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

const historyTenant = "history.test"

// historyModes covers password logins without sessions and installation-bound
// sessions, which open their sessions through different code.
var historyModes = []authkit.SessionMode{authkit.SessionDisabled, authkit.SessionRequired}

// historyKit returns a kit for mode that records sign-ins when record is set.
func historyKit(t *testing.T, db *sql.DB, mode authkit.SessionMode, record bool, m metrics.Metrics) *authkit.AuthKit {
	t.Helper()
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
		},
		APIKeyConfig:   authkit.APIKeyConfig{HMACSecret: "integration-api-hmac-secret-at-least-32-bytes"},
		PasswordConfig: authkit.PasswordConfig{BcryptCost: 4},
		SessionConfig:  authkit.SessionConfig{Mode: mode, Namespace: namespace, AbsoluteLifetime: 2 * time.Hour},
		Metrics:        m,
		RecordSignIns:  record,
	})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// historyFixture builds the schema for mode, with migration 000007 when migrate is
// set, and seeds admin@history.test with an Admin membership of history.test.
func historyFixture(t *testing.T, mode authkit.SessionMode, migrate bool) (*sql.DB, *repository.Repository, string) {
	t.Helper()
	db := openTestDB(t)
	t.Cleanup(func() { applyMigration(t, db, "000001_identity_schema.down.sql"); _ = db.Close() })
	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)
	if mode != authkit.SessionDisabled {
		applyMigration(t, db, "000002_installation_sessions.up.sql")
		applyMigration(t, db, "000003_session_sign_in.up.sql")
	}
	if migrate {
		applyMigration(t, db, "000007_sign_in_events.up.sql")
	}
	repo := repository.New(db, db)
	return db, &repo, createTenantAndUser(t, context.Background(), &repo, historyTenant)
}

var historyInfo = &model.SessionInfo{IPAddress: "[2001:db8::7]:51234", UserAgent: "Agent/1.0", DeviceName: "Work laptop"}

// historyLogin signs admin@history.test in with password (into tenantID, or by
// email when tenantID is ""), returning the session record if one was opened.
func historyLogin(k *authkit.AuthKit, mode authkit.SessionMode, password, tenantID string) (*model.Session, error) {
	ctx := context.Background()
	email := "admin@" + historyTenant
	installation := model.InstallationBinding{InstallationID: "laptop"}
	switch {
	case mode == authkit.SessionDisabled && tenantID != "":
		_, err := k.AuthService().Login(ctx, model.LoginRequest{Email: email, Password: password, TenantID: tenantID, SessionInfo: historyInfo})
		return nil, err
	case mode == authkit.SessionDisabled:
		_, err := k.AuthService().LoginByEmail(ctx, model.LoginByEmailRequest{Email: email, Password: password, SessionInfo: historyInfo})
		return nil, err
	case tenantID != "":
		resp, err := k.InstallationAuthService().LoginWithInstallation(ctx, model.InstallationLoginRequest{
			LoginRequest: model.LoginRequest{Email: email, Password: password, TenantID: tenantID, SessionInfo: historyInfo},
			Installation: installation,
		})
		if err != nil {
			return nil, err
		}
		return resp.Session, nil
	default:
		resp, err := k.InstallationAuthService().LoginByEmailWithInstallation(ctx, model.InstallationLoginByEmailRequest{
			LoginByEmailRequest: model.LoginByEmailRequest{Email: email, Password: password, SessionInfo: historyInfo},
			Installation:        installation,
		})
		if err != nil {
			return nil, err
		}
		return resp.Session, nil
	}
}

func history(t *testing.T, k *authkit.AuthKit, userID string) []*model.SignInEvent {
	t.Helper()
	events, err := k.SignInHistoryService().List(context.Background(), userID, 200, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return events
}

func checkEvent(t *testing.T, e *model.SignInEvent, method, failure, tenantID string) {
	t.Helper()
	if e.Method != method || e.Succeeded != (failure == "") || e.FailureReason != failure || e.TenantID != tenantID {
		t.Fatalf("event %+v, want method %q, failure %q, workspace %q", e, method, failure, tenantID)
	}
}

// Password logins record successes with the session they opened and where they
// came from, and refusals with their reason, newest first.
func TestSignInHistoryRecordsPasswordLogins(t *testing.T) {
	for _, mode := range historyModes {
		t.Run(modeName(mode), func(t *testing.T) {
			ctx := context.Background()
			db, repo, userID := historyFixture(t, mode, true)
			k := historyKit(t, db, mode, true, nil)

			session, err := historyLogin(k, mode, "ValidPass1!", historyTenant)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := historyLogin(k, mode, "WrongPass1!", historyTenant); !errors.Is(err, authkit.ErrInvalidCredentials) {
				t.Fatalf("wrong password: %v", err)
			}
			if _, err := historyLogin(k, mode, "ValidPass1!", "elsewhere.test"); !errors.Is(err, authkit.ErrNoActiveMembership) {
				t.Fatalf("workspace without a membership: %v", err)
			}
			// With two workspaces and none named, the sign-in selects none.
			if err := repo.CreateTenant(ctx, model.CreateTenantRequest{TenantID: "second.test", Name: "Second", AllowedDomains: []string{"second.test"}}); err != nil {
				t.Fatal(err)
			}
			grantMembership(t, ctx, repo, userID, "second.test", []string{"Member"})
			byEmail, err := historyLogin(k, mode, "ValidPass1!", "")
			if err != nil {
				t.Fatal(err)
			}

			events := history(t, k, userID)
			if len(events) != 4 {
				t.Fatalf("%d events, want 4", len(events))
			}
			checkEvent(t, events[0], "password", "", "")
			checkEvent(t, events[1], "password", model.SignInFailureNoMembership, "elsewhere.test")
			checkEvent(t, events[2], "password", model.SignInFailureBadPassword, historyTenant)
			checkEvent(t, events[3], "password", "", historyTenant)
			for i := 1; i < len(events); i++ {
				if events[i].OccurredAt.After(events[i-1].OccurredAt) {
					t.Fatal("history must be newest first")
				}
			}

			ok := events[3]
			if ok.UserID != userID || ok.IPAddress != "2001:db8::7" || ok.UserAgent != "Agent/1.0" || ok.DeviceName != "Work laptop" {
				t.Fatalf("where from: %+v", ok)
			}
			if mode == authkit.SessionDisabled {
				if ok.SessionID != "" || ok.InstallationID != "" || ok.Namespace != "" {
					t.Fatalf("no session record without session support: %+v", ok)
				}
			} else {
				if ok.SessionID != session.ID || events[0].SessionID != byEmail.ID || ok.InstallationID != "laptop" || ok.Namespace != "app" {
					t.Fatalf("session, installation and namespace: %+v", ok)
				}
				if events[2].SessionID != "" || events[2].InstallationID != "laptop" {
					t.Fatalf("a refusal opens no session but keeps its installation: %+v", events[2])
				}
			}

			// Pages follow the same order.
			page, err := k.SignInHistoryService().List(ctx, userID, 2, 1)
			if err != nil || len(page) != 2 || page[0].ID != events[1].ID || page[1].ID != events[2].ID {
				t.Fatalf("second page: %v, %v", page, err)
			}
		})
	}
}

// OpenSession records the application's method, and its refusals of an account it
// already identified.
func TestSignInHistoryRecordsVerifiedSignIns(t *testing.T) {
	for _, mode := range historyModes {
		t.Run(modeName(mode), func(t *testing.T) {
			ctx := context.Background()
			db, _, userID := historyFixture(t, mode, true)
			k := historyKit(t, db, mode, true, nil)

			resp, err := k.VerifiedLoginService().OpenSession(ctx, model.OpenSessionRequest{UserID: userID, SignInMethod: "Google", SessionInfo: historyInfo})
			if err != nil {
				t.Fatal(err)
			}
			if err := k.UserService().Disable(ctx, userID); err != nil {
				t.Fatal(err)
			}
			if _, err := k.VerifiedLoginService().OpenSession(ctx, model.OpenSessionRequest{UserID: userID, SignInMethod: "email_link"}); !errors.Is(err, authkit.ErrAccountDisabled) {
				t.Fatalf("disabled account: %v", err)
			}

			events := history(t, k, userID)
			if len(events) != 2 {
				t.Fatalf("%d events, want 2", len(events))
			}
			checkEvent(t, events[0], "email_link", model.SignInFailureAccountDisabled, "")
			checkEvent(t, events[1], "google", "", historyTenant)
			if mode != authkit.SessionDisabled && events[1].SessionID != resp.Session.ID {
				t.Fatalf("session %q, want %q", events[1].SessionID, resp.Session.ID)
			}
		})
	}
}

// A disabled or locked account is refused with the same generic error as a wrong
// password; the history keeps the real reason. An email with no account leaves no
// row anywhere.
func TestSignInHistoryRecordsAccountRefusals(t *testing.T) {
	ctx := context.Background()
	db, _, userID := historyFixture(t, authkit.SessionDisabled, true)
	k := historyKit(t, db, authkit.SessionDisabled, true, nil)

	if err := k.UserService().Lock(ctx, userID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant); !errors.Is(err, authkit.ErrInvalidCredentials) {
		t.Fatalf("locked: %v", err)
	}
	if err := k.UserService().Unlock(ctx, userID); err != nil {
		t.Fatal(err)
	}
	if err := k.UserService().Disable(ctx, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant); !errors.Is(err, authkit.ErrInvalidCredentials) {
		t.Fatalf("disabled: %v", err)
	}
	if _, err := k.AuthService().Login(ctx, model.LoginRequest{Email: "nobody@" + historyTenant, Password: "ValidPass1!", TenantID: historyTenant}); !errors.Is(err, authkit.ErrInvalidCredentials) {
		t.Fatalf("unknown email: %v", err)
	}

	events := history(t, k, userID)
	if len(events) != 2 {
		t.Fatalf("%d events, want 2", len(events))
	}
	checkEvent(t, events[0], "password", model.SignInFailureAccountDisabled, historyTenant)
	checkEvent(t, events[1], "password", model.SignInFailureAccountLocked, historyTenant)
	if n := countRows(t, db, "SELECT count(*) FROM authkit.sign_in_events"); n != 2 {
		t.Fatalf("%d rows in all, want 2: an unknown email must not be recorded", n)
	}
}

// Client text that PostgreSQL would refuse is cleaned, so an attempt cannot keep
// itself out of the history with a NUL byte or a malformed address.
func TestSignInHistoryStoresHostileClientText(t *testing.T) {
	db, _, userID := historyFixture(t, authkit.SessionDisabled, true)
	m := &countingMetrics{}
	k := historyKit(t, db, authkit.SessionDisabled, true, m)

	_, err := k.AuthService().Login(context.Background(), model.LoginRequest{
		Email: "admin@" + historyTenant, Password: "WrongPass1!", TenantID: historyTenant + "\x00",
		SessionInfo: &model.SessionInfo{IPAddress: "999.1.1.1", UserAgent: "bot\x00\xff", DeviceName: "\x00"},
	})
	if !errors.Is(err, authkit.ErrInvalidCredentials) {
		t.Fatal(err)
	}
	events := history(t, k, userID)
	if len(events) != 1 || m.get(metrics.CounterBestEffortWriteFailure+"|op=record_sign_in") != 0 {
		t.Fatalf("%d events, %d failed writes", len(events), m.get(metrics.CounterBestEffortWriteFailure+"|op=record_sign_in"))
	}
	if e := events[0]; e.IPAddress != "" || e.UserAgent != "bot" || e.DeviceName != "" || e.TenantID != historyTenant {
		t.Fatalf("stored %+v", e)
	}
}

// Without RecordSignIns nothing is written, so the table need not exist; with it
// and no table, sign-ins still work and the failed writes are counted.
func TestSignInHistoryIsOptional(t *testing.T) {
	db, _, _ := historyFixture(t, authkit.SessionDisabled, true)
	if _, err := historyLogin(historyKit(t, db, authkit.SessionDisabled, false, nil), authkit.SessionDisabled, "ValidPass1!", historyTenant); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, db, "SELECT count(*) FROM authkit.sign_in_events"); n != 0 {
		t.Fatalf("recorded %d sign-ins with RecordSignIns off", n)
	}

	db, _, userID := historyFixture(t, authkit.SessionDisabled, false)
	m := &countingMetrics{}
	k := historyKit(t, db, authkit.SessionDisabled, true, m)
	if _, err := historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant); err != nil {
		t.Fatalf("a missing history table must not fail a sign-in: %v", err)
	}
	if _, err := historyLogin(k, authkit.SessionDisabled, "WrongPass1!", historyTenant); !errors.Is(err, authkit.ErrInvalidCredentials) {
		t.Fatalf("a missing history table must not change a refusal: %v", err)
	}
	if got := m.get(metrics.CounterBestEffortWriteFailure + "|op=record_sign_in"); got != 2 {
		t.Fatalf("failed history writes counted %d times, want 2", got)
	}
	if _, err := k.SignInHistoryService().List(context.Background(), userID, 10, 0); !errors.Is(err, authkit.ErrInternal) {
		t.Fatalf("List without the table: want ErrInternal, got %v", err)
	}
}

// Cleanup removes old rows only, and deleting a user's row deletes its history.
func TestSignInHistoryCleanup(t *testing.T) {
	ctx := context.Background()
	db, _, userID := historyFixture(t, authkit.SessionDisabled, true)
	k := historyKit(t, db, authkit.SessionDisabled, true, nil)
	for range 3 {
		if _, err := historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`UPDATE authkit.sign_in_events SET occurred_at = occurred_at - interval '2 days'
		WHERE id IN (SELECT id FROM authkit.sign_in_events ORDER BY occurred_at LIMIT 2)`); err != nil {
		t.Fatal(err)
	}
	if _, err := k.SignInHistoryService().Cleanup(ctx, 0); !errors.Is(err, authkit.ErrInvalidInput) {
		t.Fatalf("Cleanup(0): %v", err)
	}
	n, err := k.SignInHistoryService().Cleanup(ctx, 24*time.Hour)
	if err != nil || n != 2 {
		t.Fatalf("Cleanup removed %d, %v; want 2", n, err)
	}
	if left := history(t, k, userID); len(left) != 1 {
		t.Fatalf("%d events left, want 1", len(left))
	}

	if _, err := db.Exec(`DELETE FROM authkit.memberships WHERE user_id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM authkit.users WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, db, "SELECT count(*) FROM authkit.sign_in_events"); n != 0 {
		t.Fatalf("%d rows outlived their user", n)
	}
}
