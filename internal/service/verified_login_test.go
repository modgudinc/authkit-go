// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/modgudinc/authkit-go/model"
)

func TestNormalizeName(t *testing.T) {
	for in, want := range map[string]string{
		"google":       "google",
		" Google ":     "google",
		"oidc:acme":    "oidc:acme",
		"device_code":  "device_code",
		"saml.okta-2":  "saml.okta-2",
		"9to5":         "9to5",
		"PASSKEY":      "passkey",
		"email_link\t": "email_link",
	} {
		got, err := normalizeName(in)
		if err != nil || got != want {
			t.Errorf("normalizeName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "   ", "-google", ".x", "_x", "sign in", "goo/gle", "gööl", strings.Repeat("a", 65)} {
		if _, err := normalizeName(in); !errors.Is(err, model.ErrInvalidInput) {
			t.Errorf("normalizeName(%q) error = %v, want ErrInvalidInput", in, err)
		}
	}
	if got, err := normalizeName(strings.Repeat("a", 64)); err != nil || len(got) != 64 {
		t.Errorf("64 characters should be accepted: %v", err)
	}
}

func TestOpenSessionRejectsInputBeforeAnyLookup(t *testing.T) {
	user := makeUser(t, "Correct1!")
	for name, req := range map[string]model.OpenSessionRequest{
		"no method":         {UserID: user.ID},
		"bad method":        {UserID: user.ID, SignInMethod: "magic link"},
		"reserved password": {UserID: user.ID, SignInMethod: " Password "},
		"no user":           {SignInMethod: "google"},
	} {
		repo := &fakeAuthRepository{user: user}
		_, err := newTestAuthService(repo).OpenSession(context.Background(), req)
		if !errors.Is(err, model.ErrInvalidInput) {
			t.Errorf("%s: error = %v, want ErrInvalidInput", name, err)
		}
		if repo.getByIDFromPrimaryCalled {
			t.Errorf("%s: loaded the user before validating input", name)
		}
	}
	// No session support configured: an installation cannot be bound.
	repo := &fakeAuthRepository{user: user}
	_, err := newTestAuthService(repo).OpenSession(context.Background(), model.OpenSessionRequest{
		UserID: user.ID, SignInMethod: "device_code", Installation: &model.InstallationBinding{InstallationID: "cli"},
	})
	if !errors.Is(err, model.ErrSessionDisabled) || repo.getByIDFromPrimaryCalled {
		t.Fatalf("error = %v, want ErrSessionDisabled before any lookup", err)
	}
}

func TestOpenSessionAccountGates(t *testing.T) {
	future := time.Now().Add(time.Hour)
	for name, tc := range map[string]struct {
		mutate  func(*model.User)
		repoErr error
		want    error
	}{
		"unknown user":   {repoErr: model.ErrNotFound, want: model.ErrNotFound},
		"disabled":       {mutate: func(u *model.User) { u.IsEnabled = false }, want: model.ErrAccountDisabled},
		"locked":         {mutate: func(u *model.User) { u.IsLocked = true; u.LockedUntil = &future }, want: model.ErrAccountLocked},
		"locked forever": {mutate: func(u *model.User) { u.IsLocked = true }, want: model.ErrAccountLocked},
	} {
		user := makeUser(t, "Correct1!")
		if tc.mutate != nil {
			tc.mutate(user)
		}
		repo := &fakeAuthRepository{user: user, membership: makeMembership(user.ID), getByIDErr: tc.repoErr}
		_, err := newTestAuthService(repo).OpenSession(context.Background(), model.OpenSessionRequest{UserID: user.ID, SignInMethod: "google"})
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: error = %v, want %v", name, err, tc.want)
		}
		if !repo.getByIDFromPrimaryCalled {
			t.Errorf("%s: the account gate must read the primary", name)
		}
		if repo.updateLastLogin != 0 {
			t.Errorf("%s: a refused sign-in updated last_login", name)
		}
	}
}

func TestPasswordLoginRefusesUserWithoutPassword(t *testing.T) {
	user := makeUser(t, "unused")
	user.PasswordHash = ""
	repo := &fakeAuthRepository{user: user, membership: makeMembership(user.ID)}
	svc := newTestAuthService(repo)
	for _, guess := range []string{"", "Correct1!", "anything"} {
		_, err := svc.Login(context.Background(), model.LoginRequest{Email: user.Email, Password: guess, TenantID: testTenantID})
		if !errors.Is(err, model.ErrInvalidCredentials) {
			t.Fatalf("error = %v, want ErrInvalidCredentials", err)
		}
	}
	// Guesses against an account with no password are not evidence of an attack on
	// it, and must not let anyone lock its owner out.
	if repo.incFailedCalled != 0 || repo.lockCalled || user.FailedLoginCount != 0 {
		t.Fatalf("failed logins counted: %d increments, locked=%v", repo.incFailedCalled, repo.lockCalled)
	}
	if repo.updateLastLogin != 0 {
		t.Fatal("refused login updated last_login")
	}

	err := svc.ChangePassword(context.Background(), model.ChangePasswordRequest{UserID: user.ID, OldPassword: "", NewPassword: "NewPass1!"})
	if !errors.Is(err, model.ErrIncorrectPassword) {
		t.Fatalf("ChangePassword error = %v, want ErrIncorrectPassword", err)
	}
	if user.PasswordHash != "" {
		t.Fatal("ChangePassword set a password without an old one")
	}
}

func TestExternalIdentityServiceValidatesInput(t *testing.T) {
	// A nil repository proves every refusal below happens before a query.
	svc := NewExternalIdentityService(nil, nil, nil)
	ctx := context.Background()
	for name, req := range map[string]model.ResolveExternalIdentityRequest{
		"no provider":     {Subject: "1"},
		"bad provider":    {Provider: "git hub", Subject: "1"},
		"no subject":      {Provider: "github"},
		"padded subject":  {Provider: "github", Subject: "1 "},
		"long subject":    {Provider: "github", Subject: strings.Repeat("1", 256)},
		"malformed email": {Provider: "github", Subject: "1", Email: "not-an-email", EmailVerified: true},
	} {
		if _, err := svc.Resolve(ctx, req); !errors.Is(err, model.ErrInvalidInput) {
			t.Errorf("Resolve %s: error = %v, want ErrInvalidInput", name, err)
		}
	}
	if _, err := svc.Link(ctx, model.LinkExternalIdentityRequest{Provider: "github", Subject: "1"}); !errors.Is(err, model.ErrInvalidInput) {
		t.Errorf("Link without a user: %v", err)
	}
	if _, err := svc.Link(ctx, model.LinkExternalIdentityRequest{UserID: "u", Provider: "github", Subject: "1", Email: "@"}); !errors.Is(err, model.ErrInvalidInput) {
		t.Errorf("Link with a malformed email: %v", err)
	}
	if err := svc.Unlink(ctx, "", "github", "1"); !errors.Is(err, model.ErrInvalidInput) {
		t.Errorf("Unlink without a user: %v", err)
	}
	if err := svc.Unlink(ctx, "u", "", "1"); !errors.Is(err, model.ErrInvalidInput) {
		t.Errorf("Unlink without a provider: %v", err)
	}
	if _, err := svc.Get(ctx, "github", ""); !errors.Is(err, model.ErrInvalidInput) {
		t.Errorf("Get without a subject: %v", err)
	}
	if _, err := svc.ListByUser(ctx, ""); !errors.Is(err, model.ErrInvalidInput) {
		t.Errorf("ListByUser without a user: %v", err)
	}
}

func TestProviderEmail(t *testing.T) {
	if got, err := providerEmail("  Person@Example.TEST "); err != nil || got != "person@example.test" {
		t.Fatalf("providerEmail = %q, %v", got, err)
	}
	if got, err := providerEmail(""); err != nil || got != "" {
		t.Fatalf("an empty email is allowed: %q, %v", got, err)
	}
}
