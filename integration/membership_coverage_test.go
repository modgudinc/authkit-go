//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/internal/service"
	"github.com/modgudinc/authkit-go/model"
)

// seedTenant creates a tenant whose single allowed domain equals its id.
func seedTenant(t *testing.T, ctx context.Context, repo *repository.Repository, tenantID string) {
	t.Helper()
	if err := repo.CreateTenant(ctx, model.CreateTenantRequest{
		TenantID:       tenantID,
		Name:           tenantID,
		AllowedDomains: []string{tenantID},
	}); err != nil {
		t.Fatalf("create tenant %s: %v", tenantID, err)
	}
}

// seedGlobalUser creates a GLOBAL identity (no tenant/roles, no membership) and
// returns its id — for tests that exercise the membership graph directly rather than
// the login-ready createTenantAndUser* fixtures.
func seedGlobalUser(t *testing.T, ctx context.Context, repo *repository.Repository, email string) string {
	t.Helper()
	pw := service.NewPasswordService(4, nil)
	hash, err := pw.HashPassword("ValidPass1!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	id, err := repo.Create(ctx, model.CreateUserRequest{Email: email, PasswordHash: hash, DisplayName: "U"})
	if err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}
	return id
}

// TestMembershipServiceLifecycle exercises the public MembershipService surface
// (Add/Get/UpdateRoles/ListByUser/ListByTenant/CountByTenant/Remove) against a real
// schema: the idempotent re-grant, the membership token_version bumps on role change
// and revoke, the soft-revoke (suspended) semantics, and the not-found paths.
func TestMembershipServiceLifecycle(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()
	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")

	repo := repository.New(db, db)
	ms := newIntegrationAuthKit(t, db).MembershipService()

	const (
		tenantA = "ms-a.test"
		tenantB = "ms-b.test"
	)
	seedTenant(t, ctx, &repo, tenantA)
	seedTenant(t, ctx, &repo, tenantB)
	alice := seedGlobalUser(t, ctx, &repo, "alice@ms.test")
	bob := seedGlobalUser(t, ctx, &repo, "bob@ms.test")

	// Add (fresh grant) — a new active membership with a zero token_version.
	if err := ms.Add(ctx, model.AddMembershipRequest{UserID: alice, TenantID: tenantA, Roles: []string{"Viewer"}}); err != nil {
		t.Fatalf("add membership: %v", err)
	}
	m, err := ms.Get(ctx, alice, tenantA)
	if err != nil {
		t.Fatalf("get membership: %v", err)
	}
	if m.Status != model.MembershipActive || len(m.Roles) != 1 || m.Roles[0] != "Viewer" || m.TokenVersion != 0 {
		t.Fatalf("unexpected membership after Add: %+v", m)
	}

	// UpdateRoles replaces the roles and bumps the membership token_version.
	if err := ms.UpdateRoles(ctx, alice, tenantA, []string{"Editor"}); err != nil {
		t.Fatalf("update roles: %v", err)
	}
	if m, err = ms.Get(ctx, alice, tenantA); err != nil {
		t.Fatalf("get after update: %v", err)
	} else if len(m.Roles) != 1 || m.Roles[0] != "Editor" || m.TokenVersion != 1 {
		t.Fatalf("after UpdateRoles: roles=%v tokenVersion=%d, want [Editor] v1", m.Roles, m.TokenVersion)
	}

	// Add again (idempotent re-grant): replaces the roles and stays active; the roles
	// change, so the version bumps again.
	if err := ms.Add(ctx, model.AddMembershipRequest{UserID: alice, TenantID: tenantA, Roles: []string{"Admin"}}); err != nil {
		t.Fatalf("re-add membership: %v", err)
	}
	if m, err = ms.Get(ctx, alice, tenantA); err != nil {
		t.Fatalf("get after re-add: %v", err)
	} else if m.Roles[0] != "Admin" || m.Status != model.MembershipActive || m.TokenVersion != 2 {
		t.Fatalf("after re-add: %+v, want roles [Admin] active v2", m)
	}

	// Grant alice a second workspace and bob the first, to exercise the list/count paths.
	if err := ms.Add(ctx, model.AddMembershipRequest{UserID: alice, TenantID: tenantB, Roles: []string{"Member"}}); err != nil {
		t.Fatalf("add alice@B: %v", err)
	}
	if err := ms.Add(ctx, model.AddMembershipRequest{UserID: bob, TenantID: tenantA, Roles: []string{"Member"}}); err != nil {
		t.Fatalf("add bob@A: %v", err)
	}

	// ListByUser: alice's workspaces (A + B).
	if ws, err := ms.ListByUser(ctx, alice); err != nil {
		t.Fatalf("list by user: %v", err)
	} else if len(ws) != 2 {
		t.Fatalf("alice workspaces = %d, want 2", len(ws))
	}

	// ListByTenant / CountByTenant: tenantA's members (alice + bob).
	if members, err := ms.ListByTenant(ctx, tenantA); err != nil {
		t.Fatalf("list by tenant: %v", err)
	} else if len(members) != 2 {
		t.Fatalf("tenantA members = %d, want 2", len(members))
	}
	if n, err := ms.CountByTenant(ctx, tenantA); err != nil || n != 2 {
		t.Fatalf("count by tenant = %d (err %v), want 2", n, err)
	}

	// Remove soft-revokes: the row is retained as suspended and the token_version bumps.
	if err := ms.Remove(ctx, alice, tenantA); err != nil {
		t.Fatalf("remove membership: %v", err)
	}
	if m, err = ms.Get(ctx, alice, tenantA); err != nil {
		t.Fatalf("get after remove: %v", err)
	} else if m.Status != model.MembershipSuspended || m.TokenVersion != 3 {
		t.Fatalf("after Remove: status=%s tokenVersion=%d, want suspended v3", m.Status, m.TokenVersion)
	}
	// CountByTenant is status-agnostic: the suspended row still counts.
	if n, _ := ms.CountByTenant(ctx, tenantA); n != 2 {
		t.Fatalf("count after suspend = %d, want 2 (status-agnostic)", n)
	}

	// Not-found paths: Get / Remove of a membership that does not exist.
	if _, err := ms.Get(ctx, bob, tenantB); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("get non-member: expected ErrNotFound, got %v", err)
	}
	if err := ms.Remove(ctx, bob, tenantB); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("remove non-member: expected ErrNotFound, got %v", err)
	}
}

// TestAddMembershipUnknownUserOrTenant covers AddMembership's foreign-key branch: a
// user_id or tenant_id with no parent row surfaces as model.ErrNotFound rather than a
// raw FK-violation string.
func TestAddMembershipUnknownUserOrTenant(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()
	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")

	repo := repository.New(db, db)
	const tenantID = "fk.test"
	seedTenant(t, ctx, &repo, tenantID)
	userID := seedGlobalUser(t, ctx, &repo, "user@fk.test")

	// Unknown user_id -> FK violation mapped to ErrNotFound.
	if err := repo.AddMembership(ctx, model.AddMembershipRequest{
		UserID:   uuid.Must(uuid.NewV7()).String(),
		TenantID: tenantID,
		Roles:    []string{"Member"},
	}); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("add membership with unknown user: expected ErrNotFound, got %v", err)
	}

	// Unknown tenant_id -> FK violation mapped to ErrNotFound.
	if err := repo.AddMembership(ctx, model.AddMembershipRequest{
		UserID:   userID,
		TenantID: "no-such-tenant",
		Roles:    []string{"Member"},
	}); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("add membership with unknown tenant: expected ErrNotFound, got %v", err)
	}
}

// TestMintWorkspaceToken covers AuthService.MintWorkspaceToken — the
// select/switch-workspace call: minting a fresh workspace-scoped access token from an
// existing identity session (without re-login or rotating the refresh token), plus the
// invalid-session and non-member rejections.
func TestMintWorkspaceToken(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()
	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")

	repo := repository.New(db, db)
	pw := service.NewPasswordService(4, nil)
	const (
		tenantA  = "mint-a.test"
		tenantB  = "mint-b.test"
		password = "ValidPass1!"
	)
	email := "switcher@mint.test"
	userID := createTenantAndUserWithPassword(t, ctx, &repo, tenantA, email, password, pw) // active member of A
	seedTenant(t, ctx, &repo, tenantB)
	grantMembership(t, ctx, &repo, userID, tenantB, []string{"Member"}) // also an active member of B

	auth := newIntegrationAuthKit(t, db).AuthService()

	// Log in to workspace A; the refresh token is the shared identity session.
	login, err := auth.Login(ctx, model.LoginRequest{Email: email, Password: password, TenantID: tenantA})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	// Switch workspace: mint a tenantB access token from the same session (no re-login,
	// refresh token unchanged).
	ws, err := auth.MintWorkspaceToken(ctx, login.RefreshToken, tenantB)
	if err != nil {
		t.Fatalf("mint workspace token: %v", err)
	}
	if ws.TenantID != tenantB || ws.AccessToken == "" || ws.ExpiresIn <= 0 {
		t.Fatalf("unexpected workspace token response: %+v", ws)
	}
	claims, err := auth.ValidateJWT(ctx, ws.AccessToken)
	if err != nil {
		t.Fatalf("validate minted token: %v", err)
	}
	if claims.TenantID != tenantB || claims.UserID != userID {
		t.Fatalf("minted token claims: tenant=%s user=%s, want %s/%s", claims.TenantID, claims.UserID, tenantB, userID)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "Member" {
		t.Fatalf("minted token roles = %v, want [Member]", claims.Roles)
	}

	// Re-minting the original workspace from the same session also works.
	if a, err := auth.MintWorkspaceToken(ctx, login.RefreshToken, tenantA); err != nil || a.TenantID != tenantA {
		t.Fatalf("mint tenantA token: %+v err=%v", a, err)
	}

	// An unknown/garbage refresh token is rejected.
	if _, err := auth.MintWorkspaceToken(ctx, "not-a-real-refresh-token", tenantA); err == nil {
		t.Fatal("expected an unknown refresh token to be rejected")
	}

	// A workspace the identity is not a member of -> ErrNoActiveMembership.
	if _, err := auth.MintWorkspaceToken(ctx, login.RefreshToken, "stranger.test"); !errors.Is(err, model.ErrNoActiveMembership) {
		t.Fatalf("mint for non-member workspace: expected ErrNoActiveMembership, got %v", err)
	}
}
