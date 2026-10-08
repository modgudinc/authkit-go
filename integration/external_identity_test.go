//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	authkit "github.com/modgudinc/authkit-go"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
)

func resolve(t *testing.T, k *authkit.AuthKit, req model.ResolveExternalIdentityRequest) *model.ResolvedExternalIdentity {
	t.Helper()
	res, err := k.ExternalIdentityService().Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return res
}

func countRows(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestResolveCreatesUserAndSignsIn(t *testing.T) {
	db, k, _, _ := verifiedFixture(t, authkit.SessionRequired)
	ctx := context.Background()
	first := resolve(t, k, model.ResolveExternalIdentityRequest{
		Provider: " Google ", Subject: "g-1", Email: "New@Example.test", EmailVerified: true,
		DisplayName: " New Person ", CreateUser: true,
	})
	if !first.Created || !first.Linked || first.User.Email != "new@example.test" || first.User.DisplayName != "New Person" || first.User.HasPassword() {
		t.Fatalf("expected a new passwordless user: %+v", first.User)
	}
	if first.Identity.Provider != "google" || first.Identity.Subject != "g-1" || first.Identity.UserID != first.User.ID || first.Identity.LastSignInAt == nil {
		t.Fatalf("identity: %+v", first.Identity)
	}

	// A returning sign-in is found by subject alone; the provider's new address only
	// updates the link's snapshot, never the user's email.
	again := resolve(t, k, model.ResolveExternalIdentityRequest{Provider: "google", Subject: "g-1", Email: "renamed@example.test", EmailVerified: false, CreateUser: true})
	if again.Created || again.Linked || again.User.ID != first.User.ID {
		t.Fatalf("returning sign-in: %+v", again)
	}
	user, err := k.UserService().GetByID(ctx, first.User.ID)
	if err != nil || user.Email != "new@example.test" {
		t.Fatalf("user email changed: %+v, %v", user, err)
	}
	stored, err := k.ExternalIdentityService().Get(ctx, "GOOGLE", "g-1")
	if err != nil || stored.Email != "renamed@example.test" || stored.EmailVerified || !stored.LastSignInAt.After(*first.Identity.LastSignInAt) {
		t.Fatalf("stored link: %+v, %v", stored, err)
	}
	// Subjects are case-sensitive.
	_, err = k.ExternalIdentityService().Get(ctx, "google", "G-1")
	requireError(t, err, authkit.ErrNotFound)

	// No workspace yet: a session, and an access token once the app grants one.
	resp := openSession(t, k, model.OpenSessionRequest{UserID: first.User.ID, SignInMethod: "google"})
	if resp.AccessToken != "" || resp.Session == nil || resp.Session.SignInMethod != "google" {
		t.Fatalf("new user session: %+v", resp)
	}
	repo := repository.New(db, db)
	grantMembership(t, ctx, &repo, first.User.ID, "sessions.test", []string{"Member"})
	ws, err := k.AuthService().MintWorkspaceToken(ctx, resp.RefreshToken, "sessions.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.AuthService().ValidateJWT(ctx, ws.AccessToken); err != nil {
		t.Fatal(err)
	}
	_, err = k.InstallationAuthService().LoginWithInstallation(ctx, model.InstallationLoginRequest{
		LoginRequest: model.LoginRequest{Email: "new@example.test", Password: "", TenantID: "sessions.test"},
		Installation: model.InstallationBinding{InstallationID: "mac"},
	})
	requireError(t, err, authkit.ErrInvalidCredentials)
}

func TestResolveUnverifiedEmail(t *testing.T) {
	db, k, _, _ := verifiedFixture(t, authkit.SessionDisabled)
	ctx := context.Background()
	svc := k.ExternalIdentityService()

	_, err := svc.Resolve(ctx, model.ResolveExternalIdentityRequest{Provider: "github", Subject: "7", Email: "someone@example.test", CreateUser: true})
	requireError(t, err, authkit.ErrEmailNotVerified)
	_, err = svc.Resolve(ctx, model.ResolveExternalIdentityRequest{Provider: "github", Subject: "7", EmailVerified: true, CreateUser: true})
	requireError(t, err, authkit.ErrEmailNotVerified)
	_, err = svc.Resolve(ctx, model.ResolveExternalIdentityRequest{Provider: "github", Subject: "7", Email: "someone@example.test"})
	requireError(t, err, authkit.ErrNotFound)

	// An unverified address never finds an account, even one that could be linked.
	if _, err := k.UserService().Create(ctx, model.CreateUserRequest{Email: "magic@example.test", DisplayName: "Magic"}); err != nil {
		t.Fatal(err)
	}
	_, err = svc.Resolve(ctx, model.ResolveExternalIdentityRequest{Provider: "github", Subject: "7", Email: "magic@example.test"})
	requireError(t, err, authkit.ErrNotFound)
	_, err = svc.Resolve(ctx, model.ResolveExternalIdentityRequest{Provider: "github", Subject: "7", Email: "magic@example.test", CreateUser: true})
	requireError(t, err, authkit.ErrEmailNotVerified)
	// A verified email that matches nobody, without CreateUser.
	_, err = svc.Resolve(ctx, model.ResolveExternalIdentityRequest{Provider: "github", Subject: "7", Email: "nobody@example.test", EmailVerified: true})
	requireError(t, err, authkit.ErrNotFound)

	if n := countRows(t, db, "SELECT count(*) FROM authkit.external_identities"); n != 0 {
		t.Fatalf("refused sign-ins left %d links", n)
	}
	if exists, err := k.UserService().Exists(ctx, "someone@example.test"); err != nil || exists {
		t.Fatalf("an unverified sign-in created a user: %v", err)
	}
}

func TestResolveLinksPasswordlessUser(t *testing.T) {
	_, k, m, _ := verifiedFixture(t, authkit.SessionOptional)
	ctx := context.Background()
	id, err := k.UserService().Create(ctx, model.CreateUserRequest{Email: "magic@example.test", DisplayName: "Magic"})
	if err != nil {
		t.Fatal(err)
	}
	res := resolve(t, k, model.ResolveExternalIdentityRequest{Provider: "github", Subject: "42", Email: "MAGIC@example.test", EmailVerified: true})
	if res.Created || !res.Linked || res.User.ID != id {
		t.Fatalf("expected the existing user to be linked: %+v", res)
	}
	// A second provider links by the same rules.
	res = resolve(t, k, model.ResolveExternalIdentityRequest{Provider: "google", Subject: "g-42", Email: "magic@example.test", EmailVerified: true, CreateUser: true})
	if res.Created || !res.Linked || res.User.ID != id {
		t.Fatalf("second provider: %+v", res)
	}

	// The provider reassigned the address to a different account: refused, not linked.
	_, err = k.ExternalIdentityService().Resolve(ctx, model.ResolveExternalIdentityRequest{Provider: "google", Subject: "g-recycled", Email: "magic@example.test", EmailVerified: true, CreateUser: true})
	requireError(t, err, authkit.ErrIdentityLinkRequired)
	if m.get(metrics.CounterIdentityLinkRefused+"|reason=provider_account_mismatch") != 1 {
		t.Fatal("refusal not counted")
	}
	links, err := k.ExternalIdentityService().ListByUser(ctx, id)
	if err != nil || len(links) != 2 || links[0].Provider != "github" || links[1].Provider != "google" {
		t.Fatalf("links: %+v, %v", links, err)
	}
}

func TestResolveRefusesUserWithPassword(t *testing.T) {
	db, k, m, adminID := verifiedFixture(t, authkit.SessionRequired)
	ctx := context.Background()
	svc := k.ExternalIdentityService()
	req := model.ResolveExternalIdentityRequest{Provider: "google", Subject: "g-admin", Email: "Admin@Sessions.test", EmailVerified: true, CreateUser: true}
	_, err := svc.Resolve(ctx, req)
	requireError(t, err, authkit.ErrIdentityLinkRequired)
	if m.get(metrics.CounterIdentityLinkRefused+"|reason=has_password") != 1 {
		t.Fatal("refusal not counted")
	}
	if n := countRows(t, db, "SELECT count(*) FROM authkit.external_identities"); n != 0 {
		t.Fatal("a refused sign-in was linked")
	}

	// The owner signs in with their password, then links the identity explicitly.
	login := sessionLogin(t, k, "browser")
	linked, err := svc.Link(ctx, model.LinkExternalIdentityRequest{UserID: login.User.ID, Provider: "Google", Subject: "g-admin", Email: "admin@sessions.test", EmailVerified: true})
	if err != nil || linked.UserID != adminID || linked.LastSignInAt != nil {
		t.Fatalf("link: %+v, %v", linked, err)
	}
	res := resolve(t, k, req)
	if res.User.ID != adminID || res.Created || res.Linked {
		t.Fatalf("after link: %+v", res)
	}
	resp := openSession(t, k, model.OpenSessionRequest{UserID: res.User.ID, SignInMethod: "google"})
	if resp.TenantID != "sessions.test" || resp.Session.SignInMethod != "google" {
		t.Fatalf("session: %+v", resp)
	}
	// The password still works alongside the link.
	sessionLogin(t, k, "browser")
}

func TestLinkAndUnlink(t *testing.T) {
	_, k, _, adminID := verifiedFixture(t, authkit.SessionDisabled)
	ctx := context.Background()
	svc := k.ExternalIdentityService()
	otherID, err := k.UserService().Create(ctx, model.CreateUserRequest{Email: "other@example.test", DisplayName: "Other"})
	if err != nil {
		t.Fatal(err)
	}

	for _, req := range []model.LinkExternalIdentityRequest{
		{UserID: adminID, Provider: "", Subject: "s"},
		{UserID: adminID, Provider: "goo gle", Subject: "s"},
		{UserID: adminID, Provider: "google", Subject: ""},
		{UserID: adminID, Provider: "google", Subject: " s"},
		{UserID: adminID, Provider: "google", Subject: strings.Repeat("s", 256)},
		{UserID: "", Provider: "google", Subject: "s"},
		{UserID: adminID, Provider: "google", Subject: "s", Email: "not-an-email"},
	} {
		_, err := svc.Link(ctx, req)
		requireError(t, err, authkit.ErrInvalidInput)
	}
	_, err = svc.Link(ctx, model.LinkExternalIdentityRequest{UserID: "01a11a39-0000-7000-8000-000000000000", Provider: "google", Subject: "s"})
	requireError(t, err, authkit.ErrNotFound)

	first, err := svc.Link(ctx, model.LinkExternalIdentityRequest{UserID: adminID, Provider: "google", Subject: "s-1", Email: "a@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := svc.Link(ctx, model.LinkExternalIdentityRequest{UserID: adminID, Provider: "google", Subject: "s-1", Email: "b@example.test", EmailVerified: true})
	// CreatedAt comes back from the database at microsecond precision.
	if err != nil || again.Email != "b@example.test" || !again.EmailVerified || again.CreatedAt.Sub(first.CreatedAt).Abs() > time.Microsecond {
		t.Fatalf("relink should refresh the email only: %+v, %v", again, err)
	}
	_, err = svc.Link(ctx, model.LinkExternalIdentityRequest{UserID: otherID, Provider: "google", Subject: "s-1"})
	requireError(t, err, authkit.ErrIdentityAlreadyLinked)

	for _, link := range []model.LinkExternalIdentityRequest{
		{UserID: adminID, Provider: "google", Subject: "s-2"},
		{UserID: adminID, Provider: "github", Subject: "9"},
		{UserID: otherID, Provider: "github", Subject: "10"},
	} {
		if _, err := svc.Link(ctx, link); err != nil {
			t.Fatal(err)
		}
	}
	links, err := svc.ListByUser(ctx, adminID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var subjects []string
	for _, link := range links {
		subjects = append(subjects, link.Subject)
	}
	if want := []string{"9", "s-1", "s-2"}; !slices.Equal(subjects, want) {
		t.Fatalf("list order: %v, want %v", subjects, want)
	}
	none, err := svc.ListByUser(ctx, "01a11a39-0000-7000-8000-000000000000")
	if err != nil || none == nil || len(none) != 0 {
		t.Fatalf("unknown user should list nothing: %v", err)
	}

	// Unlink is scoped to the user that owns the link.
	requireError(t, svc.Unlink(ctx, otherID, "google", "s-1"), authkit.ErrNotFound)
	if err := svc.Unlink(ctx, adminID, "GOOGLE", "s-1"); err != nil {
		t.Fatal(err)
	}
	_, err = svc.Get(ctx, "google", "s-1")
	requireError(t, err, authkit.ErrNotFound)
	requireError(t, svc.Unlink(ctx, adminID, "google", "s-1"), authkit.ErrNotFound)
	// Once unlinked, the identity is free for another user.
	if _, err := svc.Link(ctx, model.LinkExternalIdentityRequest{UserID: otherID, Provider: "google", Subject: "s-1"}); err != nil {
		t.Fatal(err)
	}
}

func TestExternalIdentityAccountState(t *testing.T) {
	db, k, _, _ := verifiedFixture(t, authkit.SessionRequired)
	ctx := context.Background()
	res := resolve(t, k, model.ResolveExternalIdentityRequest{Provider: "google", Subject: "g-1", Email: "gone@example.test", EmailVerified: true, CreateUser: true})

	// Resolve finds a disabled user; OpenSession refuses it.
	if err := k.UserService().Delete(ctx, res.User.ID); err != nil {
		t.Fatal(err)
	}
	again := resolve(t, k, model.ResolveExternalIdentityRequest{Provider: "google", Subject: "g-1", Email: "gone@example.test", EmailVerified: true})
	if again.User.ID != res.User.ID || again.User.IsEnabled {
		t.Fatalf("resolve of a disabled user: %+v", again.User)
	}
	_, err := k.VerifiedLoginService().OpenSession(ctx, model.OpenSessionRequest{UserID: again.User.ID, SignInMethod: "google"})
	requireError(t, err, authkit.ErrAccountDisabled)

	// Removing the user removes its links.
	if _, err := db.Exec("DELETE FROM authkit.users WHERE id=$1", res.User.ID); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, db, "SELECT count(*) FROM authkit.external_identities WHERE user_id=$1", res.User.ID); n != 0 {
		t.Fatal("links outlived their user")
	}

	_, err = k.ExternalIdentityService().Resolve(ctx, model.ResolveExternalIdentityRequest{
		Provider: "google", Subject: "g-2", Email: "long@example.test", EmailVerified: true, CreateUser: true,
		DisplayName: strings.Repeat("n", 256),
	})
	requireError(t, err, authkit.ErrValueTooLong)
}

func TestResolveConcurrentFirstSignIns(t *testing.T) {
	db, k, _, _ := verifiedFixture(t, authkit.SessionDisabled)
	ctx := context.Background()
	run := func(reqs []model.ResolveExternalIdentityRequest) []*model.ResolvedExternalIdentity {
		results := make([]*model.ResolvedExternalIdentity, len(reqs))
		errs := make([]error, len(reqs))
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i, req := range reqs {
			wg.Add(1)
			go func(i int, req model.ResolveExternalIdentityRequest) {
				defer wg.Done()
				<-start
				results[i], errs[i] = k.ExternalIdentityService().Resolve(ctx, req)
			}(i, req)
		}
		close(start)
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				t.Fatalf("concurrent resolve: %v", err)
			}
		}
		return results
	}

	// The same first sign-in, several times at once: one user, created once.
	same := make([]model.ResolveExternalIdentityRequest, 8)
	for i := range same {
		same[i] = model.ResolveExternalIdentityRequest{Provider: "google", Subject: "g-1", Email: "race@example.test", EmailVerified: true, CreateUser: true}
	}
	created := 0
	for _, res := range run(same) {
		if res.Created {
			created++
		}
	}
	if created != 1 || countRows(t, db, "SELECT count(*) FROM authkit.users WHERE email='race@example.test'") != 1 {
		t.Fatalf("expected one user created once, got %d creations", created)
	}

	// Two providers' first sign-ins for one new address: one user with both links.
	both := run([]model.ResolveExternalIdentityRequest{
		{Provider: "google", Subject: "g-2", Email: "pair@example.test", EmailVerified: true, CreateUser: true},
		{Provider: "github", Subject: "2", Email: "pair@example.test", EmailVerified: true, CreateUser: true},
	})
	if both[0].User.ID != both[1].User.ID || !both[0].Linked || !both[1].Linked {
		t.Fatalf("expected one user for both providers: %+v, %+v", both[0], both[1])
	}
	if countRows(t, db, "SELECT count(*) FROM authkit.external_identities WHERE user_id=$1", both[0].User.ID) != 2 {
		t.Fatal("expected both links")
	}
}

func TestExternalIdentityMigration(t *testing.T) {
	db := openTestDB(t)
	t.Cleanup(func() { applyMigration(t, db, "000001_identity_schema.down.sql"); _ = db.Close() })
	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")
	k := verifiedKit(t, db, authkit.SessionDisabled, nil)
	// Without the migration the calls fail cleanly, without leaking SQL.
	_, err := k.ExternalIdentityService().Resolve(context.Background(), model.ResolveExternalIdentityRequest{Provider: "google", Subject: "g", Email: "a@example.test", EmailVerified: true, CreateUser: true})
	requireError(t, err, authkit.ErrInternal)

	applyMigration(t, db, "000004_external_identities.up.sql")
	applyMigration(t, db, "000004_external_identities.up.sql") // idempotent
	resolve(t, k, model.ResolveExternalIdentityRequest{Provider: "google", Subject: "g", Email: "a@example.test", EmailVerified: true, CreateUser: true})
	applyMigration(t, db, "000004_external_identities.down.sql")
	applyMigration(t, db, "000004_external_identities.down.sql")
	applyMigration(t, db, "000004_external_identities.up.sql")
	if n := countRows(t, db, "SELECT count(*) FROM authkit.external_identities"); n != 0 {
		t.Fatal("down migration kept links")
	}
}
