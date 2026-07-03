//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	authkit "github.com/modgudinc/authkit-go"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/model"
)

const roleAdmin = "Admin"

// setupGuardedMembership provisions a clean schema and returns the MembershipService
// plus the repo (for direct seeding). The caller closes db via the returned cleanup.
func setupGuardedMembership(t *testing.T) (context.Context, authkit.MembershipService, *repository.Repository) {
	t.Helper()
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	})
	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")

	repo := repository.New(db, db)
	ms := newIntegrationAuthKit(t, db).MembershipService()
	return ctx, ms, &repo
}

// grantRole seeds a global user and grants them an ACTIVE membership in tenant with
// the given roles, returning the user id.
func grantRole(t *testing.T, ctx context.Context, ms authkit.MembershipService, repo *repository.Repository, tenant, email string, roles ...string) string {
	t.Helper()
	uid := seedGlobalUser(t, ctx, repo, email)
	if err := ms.Add(ctx, model.AddMembershipRequest{UserID: uid, TenantID: tenant, Roles: roles}); err != nil {
		t.Fatalf("grant %v to %s: %v", roles, email, err)
	}
	return uid
}

// countActiveRoleHolders returns how many of the tenant's members are active and hold
// role — the invariant the guard protects.
func countActiveRoleHolders(t *testing.T, ctx context.Context, ms authkit.MembershipService, tenant, role string) int {
	t.Helper()
	members, err := ms.ListByTenant(ctx, tenant)
	if err != nil {
		t.Fatalf("list by tenant: %v", err)
	}
	n := 0
	for _, m := range members {
		if m.Status != model.MembershipActive {
			continue
		}
		for _, r := range m.Roles {
			if r == role {
				n++
				break
			}
		}
	}
	return n
}

// TestRemoveGuardedBlocksLastActiveAdmin: removing one of two Admins is allowed, but
// removing the sole remaining Admin is refused with ErrLastRoleHolder and rolled back.
func TestRemoveGuardedBlocksLastActiveAdmin(t *testing.T) {
	ctx, ms, repo := setupGuardedMembership(t)
	const tenant = "guard-remove.test"
	seedTenant(t, ctx, repo, tenant)
	alice := grantRole(t, ctx, ms, repo, tenant, "alice@guard-remove.test", roleAdmin)
	bob := grantRole(t, ctx, ms, repo, tenant, "bob@guard-remove.test", roleAdmin)

	// Two admins -> removing one is fine (one still remains).
	if err := ms.RemoveGuarded(ctx, alice, tenant, roleAdmin); err != nil {
		t.Fatalf("remove alice (one admin remains): %v", err)
	}
	if got := countActiveRoleHolders(t, ctx, ms, tenant, roleAdmin); got != 1 {
		t.Fatalf("active admins after removing alice = %d, want 1", got)
	}

	// Bob is now the last active admin -> removal refused and rolled back.
	if err := ms.RemoveGuarded(ctx, bob, tenant, roleAdmin); !errors.Is(err, model.ErrLastRoleHolder) {
		t.Fatalf("remove last admin: expected ErrLastRoleHolder, got %v", err)
	}
	m, err := ms.Get(ctx, bob, tenant)
	if err != nil {
		t.Fatalf("get bob after blocked removal: %v", err)
	}
	if m.Status != model.MembershipActive {
		t.Fatalf("bob status after blocked removal = %s, want active (rollback)", m.Status)
	}
	if got := countActiveRoleHolders(t, ctx, ms, tenant, roleAdmin); got != 1 {
		t.Fatalf("active admins after blocked removal = %d, want 1 (unchanged)", got)
	}
}

// TestRemoveGuardedAllowsNonHolder: the guard only protects holders of requireRole, so
// removing a non-Admin is allowed even when there is a single Admin.
func TestRemoveGuardedAllowsNonHolder(t *testing.T) {
	ctx, ms, repo := setupGuardedMembership(t)
	const tenant = "guard-nonholder.test"
	seedTenant(t, ctx, repo, tenant)
	grantRole(t, ctx, ms, repo, tenant, "admin@guard-nonholder.test", roleAdmin)
	viewer := grantRole(t, ctx, ms, repo, tenant, "viewer@guard-nonholder.test", "Viewer")

	if err := ms.RemoveGuarded(ctx, viewer, tenant, roleAdmin); err != nil {
		t.Fatalf("remove non-admin viewer: expected success, got %v", err)
	}
	m, err := ms.Get(ctx, viewer, tenant)
	if err != nil {
		t.Fatalf("get viewer: %v", err)
	}
	if m.Status != model.MembershipSuspended {
		t.Fatalf("viewer status = %s, want suspended", m.Status)
	}
}

// TestUpdateRolesGuardedBlocksLastAdminDemotion: demoting one of two Admins is allowed;
// demoting the sole remaining Admin is refused (roles + token_version unchanged), while
// promoting a member INTO Admin is always allowed.
func TestUpdateRolesGuardedBlocksLastAdminDemotion(t *testing.T) {
	ctx, ms, repo := setupGuardedMembership(t)
	const tenant = "guard-demote.test"
	seedTenant(t, ctx, repo, tenant)
	alice := grantRole(t, ctx, ms, repo, tenant, "alice@guard-demote.test", roleAdmin)
	bob := grantRole(t, ctx, ms, repo, tenant, "bob@guard-demote.test", roleAdmin)

	// Demote alice (bob still Admin) -> allowed.
	if err := ms.UpdateRolesGuarded(ctx, alice, tenant, []string{"Viewer"}, roleAdmin); err != nil {
		t.Fatalf("demote alice (bob remains admin): %v", err)
	}

	// Demoting bob (the last Admin) is refused and rolled back.
	before, err := ms.Get(ctx, bob, tenant)
	if err != nil {
		t.Fatalf("get bob before: %v", err)
	}
	if err := ms.UpdateRolesGuarded(ctx, bob, tenant, []string{"Viewer"}, roleAdmin); !errors.Is(err, model.ErrLastRoleHolder) {
		t.Fatalf("demote last admin: expected ErrLastRoleHolder, got %v", err)
	}
	after, err := ms.Get(ctx, bob, tenant)
	if err != nil {
		t.Fatalf("get bob after: %v", err)
	}
	if len(after.Roles) != 1 || after.Roles[0] != roleAdmin {
		t.Fatalf("bob roles after blocked demotion = %v, want [Admin] (rollback)", after.Roles)
	}
	if after.TokenVersion != before.TokenVersion {
		t.Fatalf("bob token_version bumped on blocked demotion: %d -> %d (rollback should keep it)", before.TokenVersion, after.TokenVersion)
	}

	// Promoting alice back into Admin is always allowed (guard is about the post-state).
	if err := ms.UpdateRolesGuarded(ctx, alice, tenant, []string{roleAdmin}, roleAdmin); err != nil {
		t.Fatalf("promote alice to admin: %v", err)
	}
	if got := countActiveRoleHolders(t, ctx, ms, tenant, roleAdmin); got != 2 {
		t.Fatalf("active admins after re-promotion = %d, want 2", got)
	}
}

// TestRemoveGuardedNotFound: a missing membership surfaces ErrNotFound (the guard never
// masks it), and takes precedence over the last-holder check.
func TestRemoveGuardedNotFound(t *testing.T) {
	ctx, ms, repo := setupGuardedMembership(t)
	const tenant = "guard-notfound.test"
	seedTenant(t, ctx, repo, tenant)
	stranger := seedGlobalUser(t, ctx, repo, "stranger@guard-notfound.test")

	if err := ms.RemoveGuarded(ctx, stranger, tenant, roleAdmin); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("remove non-member: expected ErrNotFound, got %v", err)
	}
}

// TestGuardedRemovalConcurrentKeepsOneAdmin is the race proof: N goroutines each remove
// a DISTINCT Admin at once. The per-tenant advisory lock serializes the check-and-act,
// so exactly one removal (the one that would empty the workspace of Admins) is refused
// and exactly one active Admin survives. Without the lock, several removals could each
// observe another Admin still active and all commit, orphaning the tenant.
func TestGuardedRemovalConcurrentKeepsOneAdmin(t *testing.T) {
	ctx, ms, repo := setupGuardedMembership(t)
	const (
		tenant = "guard-race.test"
		n      = 5
	)
	seedTenant(t, ctx, repo, tenant)
	admins := make([]string, n)
	for i := range admins {
		admins[i] = grantRole(t, ctx, ms, repo, tenant, fmt.Sprintf("admin%d@guard-race.test", i), roleAdmin)
	}

	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range admins {
		go func(i int) {
			defer wg.Done()
			errs[i] = ms.RemoveGuarded(ctx, admins[i], tenant, roleAdmin)
		}(i)
	}
	wg.Wait()

	blocked := 0
	for i, err := range errs {
		switch {
		case err == nil:
			// removal succeeded
		case errors.Is(err, model.ErrLastRoleHolder):
			blocked++
		default:
			t.Fatalf("goroutine %d: unexpected error %v", i, err)
		}
	}
	if blocked != 1 {
		t.Fatalf("blocked removals = %d, want exactly 1 (the last admin)", blocked)
	}
	if got := countActiveRoleHolders(t, ctx, ms, tenant, roleAdmin); got != 1 {
		t.Fatalf("surviving active admins = %d, want exactly 1", got)
	}
}
