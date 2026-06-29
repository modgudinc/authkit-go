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

// TestSecretServiceRoundTrip covers the only crypto round-trip in the library:
// AES-256-GCM encrypt-at-rest, decrypt, the (tenant_id, key) AAD binding, masking,
// and the List/MarkVerified/Count/Delete surface. SecretService is constructed
// directly with a 32-byte key (the integration AuthKit has no SecretConfig).
func TestSecretServiceRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")

	repo := repository.New(db, db)
	tenantID := "secrets.test"
	adminID := createTenantAndUser(t, ctx, &repo, tenantID)

	key := []byte("0123456789abcdef0123456789abcdef") // 32-byte AES-256 key
	secrets := service.NewSecretService(&repo, key, nil)

	const provider = "openai"
	const plaintext = "sk-secretvalue-abcdef1234567890"

	saved, err := secrets.Save(ctx, model.SaveSecretRequest{
		TenantID:   tenantID,
		Key:        provider,
		PlainValue: plaintext,
		CreatedBy:  adminID,
	})
	if err != nil {
		t.Fatalf("save secret: %v", err)
	}
	if saved.MaskedValue == plaintext || !strings.Contains(saved.MaskedValue, "*") {
		t.Fatalf("expected a masked value, got %q", saved.MaskedValue)
	}

	// Encrypted at rest: the stored column is the v1 ciphertext, never the plaintext.
	var stored string
	if err := db.QueryRowContext(ctx, `SELECT encrypted_key FROM authkit.provider_keys WHERE tenant_id=$1 AND provider=$2`, tenantID, provider).Scan(&stored); err != nil {
		t.Fatalf("read stored ciphertext: %v", err)
	}
	if stored == plaintext || !strings.HasPrefix(stored, "v1:") {
		t.Fatalf("expected v1 ciphertext at rest, got %q", stored)
	}

	// Round-trip: Get decrypts back to the exact plaintext.
	got, err := secrets.Get(ctx, tenantID, provider)
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if got != plaintext {
		t.Fatalf("decrypted = %q, want %q", got, plaintext)
	}

	// AAD binding: the same ciphertext copied under a different key must NOT decrypt,
	// because the GCM additional-authenticated-data is (tenant_id, key).
	if _, err := db.ExecContext(ctx, `
		INSERT INTO authkit.provider_keys (tenant_id, provider, encrypted_key, masked_key, created_by, is_valid)
		VALUES ($1, 'copied', $2, 'masked', $3, true)
	`, tenantID, stored, adminID); err != nil {
		t.Fatalf("insert copied ciphertext: %v", err)
	}
	if _, err := secrets.Get(ctx, tenantID, "copied"); !errors.Is(err, model.ErrInternal) {
		t.Fatalf("expected AAD-bound decrypt to fail with ErrInternal, got %v", err)
	}

	// List (masked only), MarkVerified, Count.
	list, err := secrets.List(ctx, tenantID)
	if err != nil {
		t.Fatalf("list secrets: %v", err)
	}
	if len(list) < 1 {
		t.Fatalf("expected >=1 secret, got %d", len(list))
	}
	if err := secrets.MarkVerified(ctx, tenantID, provider); err != nil {
		t.Fatalf("mark verified: %v", err)
	}
	if n, err := secrets.Count(ctx, tenantID); err != nil || n < 1 {
		t.Fatalf("count = %d err %v; want >=1", n, err)
	}

	// Delete -> Get now fails.
	if err := secrets.Delete(ctx, tenantID, provider); err != nil {
		t.Fatalf("delete secret: %v", err)
	}
	if _, err := secrets.Get(ctx, tenantID, provider); err == nil {
		t.Fatal("expected get after delete to fail")
	}
}

// TestTenantServiceDomainManagement covers tenant CRUD + the allowed-domains gate
// that governs which emails may be invited/onboarded (ValidateDomainAccess), plus
// domain-format validation and normalization.
func TestTenantServiceDomainManagement(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")

	authKit := newIntegrationAuthKit(t, db)
	tenants := authKit.TenantService()

	tenantID := "domains.test"
	created, err := tenants.Create(ctx, model.CreateTenantRequest{
		TenantID:       tenantID,
		Name:           "Domains Inc",
		AllowedDomains: []string{"acme.test"},
	})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if created.TenantID != tenantID {
		t.Fatalf("created tenant id = %q, want %q", created.TenantID, tenantID)
	}

	if ok, err := tenants.Exists(ctx, tenantID); err != nil || !ok {
		t.Fatalf("exists = %v err %v; want true", ok, err)
	}
	if ok, _ := tenants.Exists(ctx, "ghost.test"); ok {
		t.Fatal("expected ghost tenant to not exist")
	}

	if err := tenants.AddAllowedDomain(ctx, tenantID, "extra.test"); err != nil {
		t.Fatalf("add domain: %v", err)
	}
	got, err := tenants.Get(ctx, tenantID)
	if err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if !sliceHas(got.AllowedDomains, "acme.test") || !sliceHas(got.AllowedDomains, "extra.test") {
		t.Fatalf("expected both domains, got %v", got.AllowedDomains)
	}

	// Domain access gate: an allowed domain passes, an unlisted one is denied.
	if err := tenants.ValidateDomainAccess(ctx, "u@extra.test", tenantID); err != nil {
		t.Fatalf("expected extra.test allowed, got %v", err)
	}
	if err := tenants.ValidateDomainAccess(ctx, "u@blocked.test", tenantID); err == nil {
		t.Fatal("expected blocked.test to be denied")
	}

	// Replace the whole list; previously-allowed domains no longer validate.
	if err := tenants.SetAllowedDomains(ctx, tenantID, []string{"only.test"}); err != nil {
		t.Fatalf("set domains: %v", err)
	}
	if err := tenants.ValidateDomainAccess(ctx, "u@extra.test", tenantID); err == nil {
		t.Fatal("expected extra.test denied after SetAllowedDomains")
	}
	if err := tenants.ValidateDomainAccess(ctx, "u@only.test", tenantID); err != nil {
		t.Fatalf("expected only.test allowed, got %v", err)
	}

	// An invalid domain format is rejected.
	if err := tenants.AddAllowedDomain(ctx, tenantID, "not a domain"); err == nil {
		t.Fatal("expected invalid domain to be rejected")
	}

	if err := tenants.UpdateName(ctx, tenantID, "Renamed Inc"); err != nil {
		t.Fatalf("update name: %v", err)
	}
	renamed, err := tenants.Get(ctx, tenantID)
	if err != nil {
		t.Fatalf("get after rename: %v", err)
	}
	if renamed.Name != "Renamed Inc" {
		t.Fatalf("name = %q, want Renamed Inc", renamed.Name)
	}

	all, err := tenants.List(ctx)
	if err != nil {
		t.Fatalf("list tenants: %v", err)
	}
	if len(all) < 1 {
		t.Fatal("expected >=1 tenant")
	}
}

// TestUserServiceCRUD covers the core user public surface: create, the tenant-scoped
// queries (GetByID/GetByEmail/Exists/ExistsActive/GetActiveUserIDByEmail/List/Count),
// Update, and the soft-Delete (the row stays but is no longer active).
func TestUserServiceCRUD(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")

	repo := repository.New(db, db)
	authKit := newIntegrationAuthKit(t, db)
	users := authKit.UserService()
	pw := service.NewPasswordService(4, nil)

	tenantID := "usercrud.test"
	createTenantAndUser(t, ctx, &repo, tenantID) // tenant + one admin user

	hash, err := pw.HashPassword("ValidPass1!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	email := "member@" + tenantID
	newID, err := users.Create(ctx, model.CreateUserRequest{
		Email:        email,
		PasswordHash: hash,
		TenantID:     tenantID,
		DisplayName:  "Member User",
		Roles:        []string{"Member"},
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if newID == "" {
		t.Fatal("expected new user id")
	}

	gotByID, err := users.GetByID(ctx, newID, tenantID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if gotByID.Email != email {
		t.Fatalf("email = %q, want %q", gotByID.Email, email)
	}
	gotByEmail, err := users.GetByEmail(ctx, email, tenantID)
	if err != nil {
		t.Fatalf("get by email: %v", err)
	}
	if gotByEmail.ID != newID {
		t.Fatalf("get-by-email id = %q, want %q", gotByEmail.ID, newID)
	}

	if ok, err := users.Exists(ctx, email, tenantID); err != nil || !ok {
		t.Fatalf("exists = %v err %v; want true", ok, err)
	}
	if ok, err := users.Exists(ctx, "nobody@"+tenantID, tenantID); err != nil || ok {
		t.Fatalf("exists(nobody) = %v err %v; want false", ok, err)
	}
	if ok, err := users.ExistsActive(ctx, email, tenantID); err != nil || !ok {
		t.Fatalf("exists active = %v err %v; want true", ok, err)
	}
	if id, err := users.GetActiveUserIDByEmail(ctx, email, tenantID); err != nil || id != newID {
		t.Fatalf("active id = %q err %v; want %q", id, err, newID)
	}

	list, err := users.List(ctx, tenantID, 0, 0) // limit 0 -> clamped to default
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(list) < 2 {
		t.Fatalf("expected >=2 users (admin + member), got %d", len(list))
	}
	if n, err := users.Count(ctx, tenantID); err != nil || n < 2 {
		t.Fatalf("count = %d err %v; want >=2", n, err)
	}

	dn := "Member Renamed"
	if err := users.Update(ctx, model.UpdateUserRequest{UserID: newID, TenantID: tenantID, DisplayName: &dn}); err != nil {
		t.Fatalf("update user: %v", err)
	}
	updated, err := users.GetByID(ctx, newID, tenantID)
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	if updated.DisplayName != dn {
		t.Fatalf("display name = %q, want %q", updated.DisplayName, dn)
	}

	// Soft delete: the row remains but is disabled and no longer "active".
	if err := users.Delete(ctx, newID, tenantID); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	afterDelete, err := users.GetByID(ctx, newID, tenantID)
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if afterDelete.IsEnabled {
		t.Fatal("expected user disabled after soft delete")
	}
	if ok, err := users.ExistsActive(ctx, email, tenantID); err != nil || ok {
		t.Fatalf("exists active after delete = %v err %v; want false", ok, err)
	}
}

// TestMaintenanceCleanups seeds one expired/old row per maintained table and asserts
// each cleanup job removes it — confirming the expiry predicates match (not just that
// the queries run). Covers the CleanupExpired family across api-keys, invitations,
// refresh tokens, verification codes, and the status-change audit trail.
func TestMaintenanceCleanups(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")

	repo := repository.New(db, db)
	authKit := newIntegrationAuthKit(t, db)

	tenantID := "cleanup.test"
	userID := createTenantAndUser(t, ctx, &repo, tenantID)

	apiKeys := authKit.APIKeyService()
	invites := authKit.InvitationService()
	tokens := authKit.TokenService()
	users := authKit.UserService()
	otp := authKit.OTPService()

	// Expired API key (create with a TTL, then backdate it).
	expiresIn := time.Hour
	ak, err := apiKeys.Create(ctx, model.CreateAPIKeyRequest{TenantID: tenantID, CreatedBy: userID, Name: "old", ExpiresIn: &expiresIn})
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE authkit.api_keys SET expires_at = NOW() - INTERVAL '1 hour' WHERE key_id=$1`, ak.KeyID); err != nil {
		t.Fatalf("backdate api key: %v", err)
	}

	// Expired invitation (create, then backdate).
	inv, err := invites.Create(ctx, model.CreateInvitationRequest{TenantID: tenantID, CreatedBy: userID, Email: "old@" + tenantID, Roles: []string{"Member"}})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	// Backdate created_at as well: the invitations table CHECKs expires_at > created_at,
	// so an expired (past) expiry must still sit after an even-earlier creation time.
	if _, err := db.ExecContext(ctx, `UPDATE authkit.invitations SET created_at = NOW() - INTERVAL '2 hours', expires_at = NOW() - INTERVAL '1 hour' WHERE code=$1`, inv.Code); err != nil {
		t.Fatalf("backdate invitation: %v", err)
	}

	// Already-expired refresh token.
	if _, err := repo.CreateRefreshToken(ctx, repository.CreateRefreshTokenRequest{
		UserID:    userID,
		TokenHash: "expired-refresh-hash",
		ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("create expired refresh token: %v", err)
	}

	// Expired verification code.
	otpEmail := "otp@" + tenantID
	if _, err := db.ExecContext(ctx, `
		INSERT INTO authkit.verification_codes (tenant_id, email, code_hash, purpose, expires_at)
		VALUES ($1, $2, $3, 'signup', NOW() - INTERVAL '1 hour')
	`, tenantID, otpEmail, strings.Repeat("a", 64)); err != nil {
		t.Fatalf("insert expired verification code: %v", err)
	}

	// Old status-change audit row (older than the 24h retention used below).
	if _, err := db.ExecContext(ctx, `
		INSERT INTO authkit.user_status_changes (id, user_id, status_type, changed_by_type, changed_at)
		VALUES ($1, $2, 'disable', 'system', NOW() - INTERVAL '48 hours')
	`, uuid.NewString(), userID); err != nil {
		t.Fatalf("insert old status change: %v", err)
	}

	// Each cleanup must remove at least the row we seeded.
	if n, err := apiKeys.CleanupExpired(ctx); err != nil || n < 1 {
		t.Fatalf("cleanup api keys: n=%d err=%v", n, err)
	}
	if n, err := invites.CleanupExpired(ctx); err != nil || n < 1 {
		t.Fatalf("cleanup invitations: n=%d err=%v", n, err)
	}
	if n, err := tokens.CleanupExpired(ctx); err != nil || n < 1 {
		t.Fatalf("cleanup refresh tokens: n=%d err=%v", n, err)
	}
	if n, err := otp.CleanupExpired(ctx); err != nil || n < 1 {
		t.Fatalf("cleanup verification codes: n=%d err=%v", n, err)
	}
	if n, err := users.CleanupStatusChanges(ctx, 24*time.Hour); err != nil || n < 1 {
		t.Fatalf("cleanup status changes: n=%d err=%v", n, err)
	}
}

// sliceHas reports whether want is present in xs.
func sliceHas(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
