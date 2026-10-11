//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/internal/service"
	"github.com/modgudinc/authkit-go/model"
)

// TestUserStatusHistoryAndAudit exercises the account status-change audit trail end
// to end. It drives the admin status mutators (Lock/Unlock/Disable/Enable, which also
// revoke refresh tokens) through the service layer, then reads the trail back via
// UserService.StatusHistory -> repo.ListUserStatusChanges. That read is the one place
// the uuid.UUID -> string migration changed a scan: nullable changed_by is now scanned
// with sql.NullString. The library always leaves changed_by NULL, so to cover BOTH
// branches of that scan this test also inserts one row with a non-NULL changed_by
// directly and asserts it decodes to a non-nil *string.
func TestUserStatusHistoryAndAudit(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	authKit := newIntegrationAuthKit(t, db)
	users := authKit.UserService()

	tenantID := "status.test"
	userID := createTenantAndUser(t, ctx, &repo, tenantID)

	// Drive four real transitions through the service layer. Each records one audit
	// row (with changed_by NULL, changed_by_type "admin") and Lock/Disable also revoke
	// refresh tokens (repo.DeleteByUserID). Status operations are identity-level (no
	// tenant) in the decoupled model.
	until := time.Now().Add(time.Hour)
	if err := users.Lock(ctx, userID, &until); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if err := users.Unlock(ctx, userID); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := users.Disable(ctx, userID); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if err := users.Enable(ctx, userID); err != nil {
		t.Fatalf("enable: %v", err)
	}

	// Insert one audit row with a NON-NULL changed_by to cover the sql.NullString
	// "Valid" branch. changed_by is an FK to users.id, so it must reference a real
	// user — reuse userID itself.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO authkit.user_status_changes (id, user_id, status_type, changed_by, changed_by_type, changed_at)
		VALUES ($1, $2, 'disable', $3, 'admin', NOW())
	`, uuid.NewString(), userID, userID); err != nil {
		t.Fatalf("insert manual status change: %v", err)
	}

	history, err := users.StatusHistory(ctx, userID)
	if err != nil {
		t.Fatalf("status history: %v", err)
	}
	// 4 library-written rows (lock, unlock, disable, enable) + 1 manual = 5.
	if len(history) < 5 {
		t.Fatalf("expected >=5 status-change rows, got %d", len(history))
	}

	var sawNullChangedBy, sawNonNullChangedBy bool
	for _, c := range history {
		if c.UserID != userID {
			t.Fatalf("status change for wrong user: got %q want %q", c.UserID, userID)
		}
		if c.ChangedByType == "" {
			t.Fatalf("changed_by_type empty on row %s", c.ID)
		}
		if c.ChangedBy == nil {
			sawNullChangedBy = true // library rows leave changed_by NULL
		} else {
			sawNonNullChangedBy = true
			if *c.ChangedBy != userID {
				t.Fatalf("manual changed_by = %q, want %q", *c.ChangedBy, userID)
			}
		}
	}
	if !sawNullChangedBy {
		t.Fatal("expected at least one library-written row with NULL changed_by (sql.NullString invalid branch)")
	}
	if !sawNonNullChangedBy {
		t.Fatal("expected the manually inserted row with non-NULL changed_by (sql.NullString valid branch)")
	}

	// Identity scoping: the audit trail is keyed by the global user id. A different
	// identity (no status transitions) has its own, empty trail — one user's trail is
	// never returned for another.
	otherID := createUserWithPassword(t, ctx, &repo, tenantID, "other@"+tenantID, "ValidPass1!", service.NewPasswordService(4, nil))
	other, err := users.StatusHistory(ctx, otherID)
	if err != nil {
		t.Fatalf("other-identity status history: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("expected empty history for an untouched identity, got %d", len(other))
	}
}

// TestAPIKeyServiceValidate covers the APIKeyService auth gate: create -> validate
// (happy path), then reject unknown, malformed, expired, and revoked keys. It also
// sweeps List/Count/Get/Revoke (all previously uncovered at the service layer).
func TestAPIKeyServiceValidate(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	authKit := newIntegrationAuthKit(t, db)
	keys := authKit.APIKeyService()

	tenantID := "apikey.test"
	adminID := createTenantAndUser(t, ctx, &repo, tenantID)

	created, err := keys.Create(ctx, model.CreateAPIKeyRequest{
		TenantID:  tenantID,
		CreatedBy: adminID,
		Name:      "ci-key",
	})
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}
	if created.APIKey == "" || created.KeyID == "" {
		t.Fatalf("unexpected create response: %+v", created)
	}

	// Happy path: the plaintext key validates to its tenant + key id.
	gotCtx, err := keys.Validate(ctx, created.APIKey)
	if err != nil {
		t.Fatalf("validate api key: %v", err)
	}
	if gotCtx.TenantID != tenantID || gotCtx.KeyID != created.KeyID {
		t.Fatalf("validate context = %+v, want tenant=%s key=%s", gotCtx, tenantID, created.KeyID)
	}

	// Well-formed but unknown key -> ErrInvalidAPIKey (hash miss).
	if _, err := keys.Validate(ctx, "sk_live_"+strings.Repeat("a", 32)); !errors.Is(err, model.ErrInvalidAPIKey) {
		t.Fatalf("validate unknown key: expected ErrInvalidAPIKey, got %v", err)
	}
	// Malformed (bad prefix/length) -> ErrInvalidAPIKey (format gate).
	if _, err := keys.Validate(ctx, "not-a-key"); !errors.Is(err, model.ErrInvalidAPIKey) {
		t.Fatalf("validate malformed key: expected ErrInvalidAPIKey, got %v", err)
	}

	// Expired key -> rejected. Create with a positive TTL, then backdate it in the DB.
	expiresIn := time.Hour
	expired, err := keys.Create(ctx, model.CreateAPIKeyRequest{
		TenantID:  tenantID,
		CreatedBy: adminID,
		Name:      "expired-key",
		ExpiresIn: &expiresIn,
	})
	if err != nil {
		t.Fatalf("create expiring key: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE authkit.api_keys SET expires_at = NOW() - INTERVAL '1 hour' WHERE key_id = $1`, expired.KeyID); err != nil {
		t.Fatalf("backdate expiry: %v", err)
	}
	if _, err := keys.Validate(ctx, expired.APIKey); !errors.Is(err, model.ErrInvalidAPIKey) {
		t.Fatalf("validate expired key: expected ErrInvalidAPIKey, got %v", err)
	}

	// List/Count/Get round-trip.
	list, err := keys.List(ctx, tenantID, true /* includeExpired */)
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}
	if len(list) < 2 {
		t.Fatalf("expected >=2 keys (incl. expired), got %d", len(list))
	}
	if _, err := keys.Count(ctx, tenantID); err != nil {
		t.Fatalf("count keys: %v", err)
	}
	got, err := keys.Get(ctx, created.KeyID, tenantID)
	if err != nil {
		t.Fatalf("get key: %v", err)
	}
	if got.KeyID != created.KeyID {
		t.Fatalf("get key id = %s, want %s", got.KeyID, created.KeyID)
	}

	// Revoke makes the key fail validation.
	if err := keys.Revoke(ctx, created.KeyID, tenantID); err != nil {
		t.Fatalf("revoke key: %v", err)
	}
	if _, err := keys.Validate(ctx, created.APIKey); !errors.Is(err, model.ErrInvalidAPIKey) {
		t.Fatalf("validate revoked key: expected ErrInvalidAPIKey, got %v", err)
	}
}

// TestInvitationServiceAcceptFlow covers the privilege-sensitive invitation redemption
// path: Create -> ListActive -> Accept (mints a user with the invitation's tenant +
// roles, bound to the target email), then asserts single-use exhaustion and the
// email-must-match guarantee, plus Revoke.
func TestInvitationServiceAcceptFlow(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	authKit := newIntegrationAuthKit(t, db)
	invites := authKit.InvitationService()
	pw := service.NewPasswordService(4, nil)

	tenantID := "invite.test"
	adminID := createTenantAndUser(t, ctx, &repo, tenantID)

	inviteeEmail := "newhire@" + tenantID
	inv, err := invites.Create(ctx, model.CreateInvitationRequest{
		TenantID:  tenantID,
		CreatedBy: adminID,
		Email:     inviteeEmail,
		Roles:     []string{"Member"},
	})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	if inv.Code == "" {
		t.Fatal("expected invitation code, got empty")
	}

	active, err := invites.ListActive(ctx, tenantID)
	if err != nil {
		t.Fatalf("list active invitations: %v", err)
	}
	if len(active) != 1 || active[0].Code != inv.Code {
		t.Fatalf("expected 1 active invitation %q, got %+v", inv.Code, active)
	}

	hash, err := pw.HashPassword("ValidPass1!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	newUserID, created, err := invites.Accept(ctx, model.AcceptInvitationRequest{
		Code:         inv.Code,
		Email:        inviteeEmail,
		DisplayName:  "New Hire",
		PasswordHash: hash,
	})
	if err != nil {
		t.Fatalf("accept invitation: %v", err)
	}
	if newUserID == "" {
		t.Fatal("expected new user id, got empty")
	}
	if !created {
		t.Fatal("expected a brand-new global identity to be created")
	}

	// The new GLOBAL identity exists (email lookup is tenant-agnostic now).
	createdUser, err := repo.GetByEmail(ctx, inviteeEmail)
	if err != nil {
		t.Fatalf("get accepted user: %v", err)
	}
	if createdUser.ID != newUserID {
		t.Fatalf("accepted user id mismatch: %s vs %s", createdUser.ID, newUserID)
	}
	// Roles live on the membership granted in the invitation's tenant.
	membership, err := repo.GetMembership(ctx, newUserID, tenantID)
	if err != nil {
		t.Fatalf("get accepted membership: %v", err)
	}
	if !membership.IsActive() || len(membership.Roles) != 1 || membership.Roles[0] != "Member" {
		t.Fatalf("expected active membership with roles [Member], got %+v", membership)
	}

	// Single-use: a second redemption fails as invalid/exhausted.
	if _, _, err := invites.Accept(ctx, model.AcceptInvitationRequest{
		Code:         inv.Code,
		Email:        inviteeEmail,
		DisplayName:  "Dup",
		PasswordHash: hash,
	}); !errors.Is(err, model.ErrInvitationInvalid) {
		t.Fatalf("second accept: expected ErrInvitationInvalid, got %v", err)
	}

	// Email-must-match: a different email cannot redeem the invitation.
	inv2, err := invites.Create(ctx, model.CreateInvitationRequest{
		TenantID:  tenantID,
		CreatedBy: adminID,
		Email:     "exact@" + tenantID,
		Roles:     []string{"Member"},
	})
	if err != nil {
		t.Fatalf("create second invitation: %v", err)
	}
	if _, _, err := invites.Accept(ctx, model.AcceptInvitationRequest{
		Code:         inv2.Code,
		Email:        "attacker@" + tenantID,
		DisplayName:  "X",
		PasswordHash: hash,
	}); !errors.Is(err, model.ErrInvitationInvalid) {
		t.Fatalf("email-mismatch accept: expected ErrInvitationInvalid, got %v", err)
	}

	// Revoke (soft-invalidate) the unused invitation.
	if err := invites.Revoke(ctx, inv2.Code); err != nil {
		t.Fatalf("revoke invitation: %v", err)
	}
	if _, _, err := invites.Accept(ctx, model.AcceptInvitationRequest{
		Code:         inv2.Code,
		Email:        "exact@" + tenantID,
		DisplayName:  "Y",
		PasswordHash: hash,
	}); !errors.Is(err, model.ErrInvitationInvalid) {
		t.Fatalf("accept after revoke: expected ErrInvitationInvalid, got %v", err)
	}
}

// TestUserServiceSecurityMutations covers the token-invalidating admin mutations in
// the decoupled model: MembershipService.UpdateRoles bumps the per-workspace
// (membership) token_version; UserService.IncrementTokenVersion bumps the identity
// token_version; and UserService.SetPassword replaces the stored hash. (UserService no
// longer has UpdateRoles — roles moved onto the membership graph.)
func TestUserServiceSecurityMutations(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	authKit := newIntegrationAuthKit(t, db)
	users := authKit.UserService()
	memberships := authKit.MembershipService()
	pw := service.NewPasswordService(4, nil)

	tenantID := "usermut.test"
	userID := createTenantAndUser(t, ctx, &repo, tenantID) // membership roles: [Admin]

	// MembershipService.UpdateRoles replaces the workspace roles and bumps the
	// MEMBERSHIP token_version (only this workspace's access tokens are invalidated).
	mBefore, err := repo.GetMembership(ctx, userID, tenantID)
	if err != nil {
		t.Fatalf("get membership before: %v", err)
	}
	if err := memberships.UpdateRoles(ctx, userID, tenantID, []string{"Member", "Viewer"}); err != nil {
		t.Fatalf("update membership roles: %v", err)
	}
	mAfter, err := repo.GetMembership(ctx, userID, tenantID)
	if err != nil {
		t.Fatalf("get membership after roles: %v", err)
	}
	if mAfter.TokenVersion <= mBefore.TokenVersion {
		t.Fatalf("UpdateRoles did not bump membership token_version (%d -> %d)", mBefore.TokenVersion, mAfter.TokenVersion)
	}
	if len(mAfter.Roles) != 2 {
		t.Fatalf("expected 2 roles after update, got %v", mAfter.Roles)
	}

	// SetPassword replaces the stored hash (identity-level).
	newHash, err := pw.HashPassword("NewValidPass1!")
	if err != nil {
		t.Fatalf("hash new password: %v", err)
	}
	if err := users.SetPassword(ctx, userID, newHash); err != nil {
		t.Fatalf("set password: %v", err)
	}
	gotHash, err := users.VerifyPassword(ctx, userID)
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}
	if gotHash != newHash {
		t.Fatal("stored password hash was not updated by SetPassword")
	}

	// IncrementTokenVersion bumps the IDENTITY token_version (full revocation across
	// every workspace).
	preBump, err := repo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("get user pre-bump: %v", err)
	}
	if err := users.IncrementTokenVersion(ctx, userID); err != nil {
		t.Fatalf("increment token version: %v", err)
	}
	postBump, err := repo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("get user post-bump: %v", err)
	}
	if postBump.TokenVersion <= preBump.TokenVersion {
		t.Fatalf("IncrementTokenVersion did not bump identity token_version (%d -> %d)", preBump.TokenVersion, postBump.TokenVersion)
	}
}

// TestRefreshTokenPairGatesAndErrors covers RefreshTokenPair beyond the happy path
// and the already-tested reuse/theft branch: the routine invalid-token error path,
// and the account-not-active security gate for both a disabled and a locked account.
// That gate is reached only when a refresh token is still valid but the account was
// cut off after issuance; it refuses before the token is consumed and leaves the
// user's refresh tokens as they were.
func TestRefreshTokenPairGatesAndErrors(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	authKit := newIntegrationAuthKit(t, db)
	tokens := authKit.TokenService()

	tenantID := "refresh.test"
	userID := createTenantAndUser(t, ctx, &repo, tenantID)

	user, err := repo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	// The token pair is workspace-scoped, so minting one needs the active membership.
	membership, err := repo.GetMembership(ctx, userID, tenantID)
	if err != nil {
		t.Fatalf("get membership: %v", err)
	}

	// 0. Happy-path rotation WITH session info, exercising the IP/user-agent/device
	// extraction branch (the other refresh tests pass a nil SessionInfo). RefreshTokenPair
	// is workspace-scoped now and rotates into tenantID.
	seed, err := tokens.GenerateTokenPair(ctx, user, membership, nil)
	if err != nil {
		t.Fatalf("seed token pair: %v", err)
	}
	rotated, err := tokens.RefreshTokenPair(ctx, seed.RefreshToken, tenantID, &model.SessionInfo{
		IPAddress:  "10.0.0.9",
		UserAgent:  "integration-agent",
		DeviceName: "integration-device",
	})
	if err != nil {
		t.Fatalf("rotate with session info: %v", err)
	}
	if rotated.RefreshToken == "" || rotated.RefreshToken == seed.RefreshToken {
		t.Fatalf("expected a rotated refresh token distinct from the original, got %+v", rotated)
	}

	// 1. Unknown/garbage refresh token -> routine invalid (not reuse) -> ErrInvalidRefreshToken.
	if _, err := tokens.RefreshTokenPair(ctx, "not-a-real-refresh-token", tenantID, nil); !errors.Is(err, model.ErrInvalidRefreshToken) {
		t.Fatalf("refresh with unknown token: expected ErrInvalidRefreshToken, got %v", err)
	}

	// 2. Account-not-active gate: DISABLED.
	// Mint a valid refresh token, then disable at the repo layer (which, unlike
	// UserService.Disable, does NOT revoke tokens), so the token survives to reach the
	// account gate inside the rotation.
	pair, err := tokens.GenerateTokenPair(ctx, user, membership, &model.SessionInfo{IPAddress: "127.0.0.1"})
	if err != nil {
		t.Fatalf("generate token pair: %v", err)
	}
	if err := repo.Disable(ctx, userID); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	before, err := repo.GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("list refresh tokens before disabled-account refresh: %v", err)
	}
	if _, err := tokens.RefreshTokenPair(ctx, pair.RefreshToken, tenantID, nil); !errors.Is(err, model.ErrInvalidRefreshToken) || !errors.Is(err, model.ErrAccountDisabled) {
		t.Fatalf("refresh on disabled account: expected ErrInvalidRefreshToken and ErrAccountDisabled, got %v", err)
	}
	// The gate refuses before consuming anything, and deletes nothing.
	active, err := repo.GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("list refresh tokens after disabled-account refresh: %v", err)
	}
	if len(active) != len(before) {
		t.Fatalf("expected the refresh tokens untouched after disabled-account refresh, got %d active, want %d", len(active), len(before))
	}

	// 3. Account-not-active gate: LOCKED.
	// Re-enable, mint a fresh token, then lock until a future time.
	if err := repo.Enable(ctx, userID); err != nil {
		t.Fatalf("re-enable user: %v", err)
	}
	reUser, err := repo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("get re-enabled user: %v", err)
	}
	pair2, err := tokens.GenerateTokenPair(ctx, reUser, membership, nil)
	if err != nil {
		t.Fatalf("generate token pair (locked case): %v", err)
	}
	until := time.Now().Add(time.Hour)
	if err := repo.Lock(ctx, userID, &until); err != nil {
		t.Fatalf("lock user: %v", err)
	}
	before, err = repo.GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("list refresh tokens before locked-account refresh: %v", err)
	}
	if _, err := tokens.RefreshTokenPair(ctx, pair2.RefreshToken, tenantID, nil); !errors.Is(err, model.ErrInvalidRefreshToken) || !errors.Is(err, model.ErrAccountLocked) {
		t.Fatalf("refresh on locked account: expected ErrInvalidRefreshToken and ErrAccountLocked, got %v", err)
	}
	active, err = repo.GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("list refresh tokens after locked-account refresh: %v", err)
	}
	if len(active) != len(before) {
		t.Fatalf("expected the refresh tokens untouched after locked-account refresh, got %d active, want %d", len(active), len(before))
	}
}
