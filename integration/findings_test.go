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

// TestCreateUserDuplicateReturnsErrUserExists covers the user-creation half of
// the duplicate-email finding: a (tenant_id, email) uniqueness conflict must
// surface model.ErrUserExists, not a raw Postgres unique-violation string.
func TestCreateUserDuplicateReturnsErrUserExists(t *testing.T) {
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
	tenantID := "dup.test"
	createTenantAndUserWithPassword(t, ctx, &repo, tenantID, "dup@dup.test", "ValidPass1!", pw)

	hash, err := pw.HashPassword("ValidPass1!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	_, err = repo.Create(ctx, model.CreateUserRequest{
		Email:        "dup@dup.test",
		PasswordHash: hash,
		TenantID:     tenantID,
		DisplayName:  "Duplicate",
		Roles:        []string{"Member"},
	})
	if !errors.Is(err, model.ErrUserExists) {
		t.Fatalf("expected ErrUserExists on duplicate create, got %v", err)
	}
}

// TestAcceptInvitationDuplicateUserReturnsErrUserExists covers the invitation
// half of the duplicate-email finding: accepting an invitation whose target
// email already has an account must return model.ErrUserExists AND leave the
// invitation unconsumed (transaction rolls back).
func TestAcceptInvitationDuplicateUserReturnsErrUserExists(t *testing.T) {
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
	tenantID := "invdup.test"
	ownerID := createTenantAndUserWithPassword(t, ctx, &repo, tenantID, "owner@invdup.test", "ValidPass1!", pw)

	// An account already exists for the email the invitation will target.
	email := "existing@invdup.test"
	createUserWithPassword(t, ctx, &repo, tenantID, email, "ValidPass1!", pw)

	code := "DUPINVITE00000000001"
	if err := repo.CreateInvitation(ctx, model.CreateInvitationRequest{
		Code:      code,
		TenantID:  tenantID,
		CreatedBy: ownerID,
		Roles:     []string{"Member"},
		Email:     email,
		ExpiresAt: time.Now().Add(time.Hour),
		MaxUses:   1,
	}); err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	_, err := repo.AcceptInvitation(ctx, code, email, "Existing User", "hashed-password")
	if !errors.Is(err, model.ErrUserExists) {
		t.Fatalf("expected ErrUserExists accepting invitation for existing email, got %v", err)
	}

	// The failed acceptance must not consume the single-use invitation.
	inv, err := repo.GetInvitation(ctx, code)
	if err != nil {
		t.Fatalf("get invitation after failed accept: %v", err)
	}
	if inv.CurrentUses != 0 {
		t.Fatalf("invitation should not be consumed on ErrUserExists, current_uses=%d", inv.CurrentUses)
	}
}

// TestGetByTokenHashReturnsRefreshTokenSentinel verifies the refresh-token
// lookup translates both not-found and expired into model.ErrInvalidRefreshToken
// (parity with every sibling Get* and RotateRefreshToken), so callers can branch
// with errors.Is instead of seeing a raw sql.ErrNoRows / bare string.
func TestGetByTokenHashReturnsRefreshTokenSentinel(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")

	repo := repository.New(db, db)

	// Unknown token hash.
	if _, err := repo.GetByTokenHash(ctx, "no-such-token-hash"); !errors.Is(err, model.ErrInvalidRefreshToken) {
		t.Fatalf("unknown hash: expected ErrInvalidRefreshToken, got %v", err)
	}

	// Expired (but not revoked) token.
	tenantID := "rt.test"
	userID := createTenantAndUser(t, ctx, &repo, tenantID)
	if _, err := repo.CreateRefreshToken(ctx, model.CreateRefreshTokenRequest{
		UserID:    userID,
		TokenHash: "expired-token-hash",
		ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("create expired refresh token: %v", err)
	}
	if _, err := repo.GetByTokenHash(ctx, "expired-token-hash"); !errors.Is(err, model.ErrInvalidRefreshToken) {
		t.Fatalf("expired hash: expected ErrInvalidRefreshToken, got %v", err)
	}
}

// TestTenantDomainMatchingIsCaseInsensitive verifies the documented
// case-insensitive domain matching: domains are lowercased on write, so a tenant
// configured with a mixed-case domain is matched by a lowercase lookup via both
// ValidateDomainAccess and GetTenantByDomain.
func TestTenantDomainMatchingIsCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")

	authKit := newIntegrationAuthKit(t, db)
	tenantSvc := authKit.TenantService()
	tenantID := "case.test"

	created, err := tenantSvc.CreateTenant(ctx, model.CreateTenantRequest{
		TenantID:       tenantID,
		Name:           "Case Test",
		AllowedDomains: []string{"Acme.COM"},
	})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	// Domains are normalized to lowercase on write.
	if len(created.AllowedDomains) != 1 || created.AllowedDomains[0] != "acme.com" {
		t.Fatalf("expected stored domain lowercased to acme.com, got %v", created.AllowedDomains)
	}

	// A lowercase email domain matches the mixed-case-configured domain.
	if err := tenantSvc.ValidateDomainAccess(ctx, "user@acme.com", tenantID); err != nil {
		t.Fatalf("expected case-insensitive domain match, got %v", err)
	}

	// Lookup by lowercase domain finds the tenant.
	got, err := tenantSvc.GetTenantByDomain(ctx, "acme.com")
	if err != nil {
		t.Fatalf("get tenant by domain: %v", err)
	}
	if got.TenantID != tenantID {
		t.Fatalf("GetTenantByDomain returned %q, want %q", got.TenantID, tenantID)
	}
}

// TestConsumeVerificationCodeRejectsExpired exercises the real repository expiry
// branch (repository/otp.go): an expired code — even with the correct value — is
// rejected and deleted, rather than only being covered by the in-memory fake.
func TestConsumeVerificationCodeRejectsExpired(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")

	repo := repository.New(db, db)
	tenantID := "otpexp.test"
	createTenantAndUser(t, ctx, &repo, tenantID)
	email := "expired@" + tenantID

	if _, err := repo.UpsertVerificationCode(ctx, model.CreateVerificationCodeRequest{
		TenantID:  tenantID,
		Email:     email,
		Code:      "123456",
		Purpose:   "signup",
		ExpiresAt: time.Now().Add(-time.Minute),
	}, 0); err != nil {
		t.Fatalf("upsert expired code: %v", err)
	}

	result, err := repo.ConsumeVerificationCode(ctx, tenantID, email, "123456", "signup", 5)
	if err != nil {
		t.Fatalf("consume expired: %v", err)
	}
	if result != model.OTPConsumeInvalid {
		t.Fatalf("expected OTPConsumeInvalid for expired code, got %v", result)
	}
	// The expired row must have been deleted by the consume path.
	if _, err := repo.GetVerificationCode(ctx, tenantID, email, "signup"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("expected expired code to be deleted (ErrNotFound), got %v", err)
	}
}

// TestMigration000002UUIDConsistency verifies the forward migration: api_keys.key_id
// becomes a UUID column, and the v7 generator + switched id defaults are in place.
func TestMigration000002UUIDConsistency(t *testing.T) {
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")
	applyMigration(t, db, "000002_uuid_consistency.up.sql")

	// key_id is now typed UUID (was VARCHAR).
	var dataType string
	if err := db.QueryRow(`
		SELECT data_type FROM information_schema.columns
		WHERE table_schema = 'authkit' AND table_name = 'api_keys' AND column_name = 'key_id'
	`).Scan(&dataType); err != nil {
		t.Fatalf("query key_id type: %v", err)
	}
	if dataType != "uuid" {
		t.Fatalf("api_keys.key_id type = %q, want uuid", dataType)
	}

	// The generator yields genuine version-7, RFC-4122-variant UUIDs.
	var v7 uuid.UUID
	if err := db.QueryRow(`SELECT authkit.uuid_generate_v7()`).Scan(&v7); err != nil {
		t.Fatalf("uuid_generate_v7: %v", err)
	}
	if v7.Version() != 7 {
		t.Fatalf("generated uuid version = %d, want 7", v7.Version())
	}
	if v7.Variant() != uuid.RFC4122 {
		t.Fatalf("generated uuid variant = %v, want RFC4122", v7.Variant())
	}

	// DB-side id defaults (including the trigger-populated tables) now use v7.
	for _, tbl := range []string{"users", "refresh_tokens", "user_status_changes", "auth_events"} {
		var def string
		if err := db.QueryRow(`
			SELECT column_default FROM information_schema.columns
			WHERE table_schema = 'authkit' AND table_name = $1 AND column_name = 'id'
		`, tbl).Scan(&def); err != nil {
			t.Fatalf("query %s.id default: %v", tbl, err)
		}
		if !strings.Contains(def, "uuid_generate_v7") {
			t.Fatalf("%s.id default = %q, want authkit.uuid_generate_v7()", tbl, def)
		}
	}
}

// TestRefreshTokenIPRoundTrip is the regression test for reading the INET
// ip_address column under the pgx driver. The hot rotation path does not SELECT
// ip_address, so a refresh token stored WITH a client IP is only ever read back
// by GetByTokenHash / GetByUserID — paths no other test exercises with a non-nil
// IP. This asserts the INET value round-trips into the model's *string field.
func TestRefreshTokenIPRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")

	repo := repository.New(db, db)
	tenantID := "ip.test"
	userID := createTenantAndUser(t, ctx, &repo, tenantID)

	ip, ua, dev := "127.0.0.1", "integration-agent", "test-device"
	if _, err := repo.CreateRefreshToken(ctx, model.CreateRefreshTokenRequest{
		UserID:     userID,
		TokenHash:  "ip-roundtrip-hash",
		IPAddress:  &ip,
		UserAgent:  &ua,
		DeviceName: &dev,
		ExpiresAt:  time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create refresh token with IP: %v", err)
	}

	// GetByTokenHash scans ip_address (INET) into *string.
	got, err := repo.GetByTokenHash(ctx, "ip-roundtrip-hash")
	if err != nil {
		t.Fatalf("GetByTokenHash with non-nil IP: %v", err)
	}
	if got.IPAddress == nil || *got.IPAddress != ip {
		t.Fatalf("GetByTokenHash ip_address = %v, want %q", got.IPAddress, ip)
	}

	// GetByUserID also scans ip_address.
	list, err := repo.GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("GetByUserID with non-nil IP: %v", err)
	}
	if len(list) != 1 || list[0].IPAddress == nil || *list[0].IPAddress != ip {
		t.Fatalf("GetByUserID ip_address = %+v, want %q", list, ip)
	}
}

// TestAPIKeyUUIDKeyIDRoundTripAndIndex covers two previously-untested things on
// the api_keys table after the 000002 (key_id -> UUID) and 000003 (drop the
// redundant key_hash index) migrations: that an API key with a UUID key_id
// inserts and reads back cleanly, and that 000003 leaves exactly the UNIQUE index
// on key_hash (the redundant idx_api_keys_key_hash is gone).
func TestAPIKeyUUIDKeyIDRoundTripAndIndex(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")
	applyMigration(t, db, "000002_uuid_consistency.up.sql")
	applyMigration(t, db, "000003_drop_redundant_api_key_hash_index.up.sql")

	repo := repository.New(db, db)
	tenantID := "apikey.test"
	createdBy := createTenantAndUser(t, ctx, &repo, tenantID)

	keyID, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("new key id: %v", err)
	}
	if err := repo.CreateAPIKey(ctx, repository.InsertAPIKeyParams{
		KeyID:     keyID.String(),
		KeyHash:   "test-key-hash",
		TenantID:  tenantID,
		Name:      "test key",
		CreatedBy: createdBy,
	}); err != nil {
		t.Fatalf("create api key with UUID key_id: %v", err)
	}

	got, err := repo.GetAPIKey(ctx, keyID.String(), tenantID)
	if err != nil {
		t.Fatalf("get api key: %v", err)
	}
	if _, err := uuid.Parse(got.KeyID); err != nil {
		t.Fatalf("returned key_id %q is not a UUID: %v", got.KeyID, err)
	}
	if got.KeyID != keyID.String() {
		t.Fatalf("key_id = %q, want %q", got.KeyID, keyID.String())
	}

	// 000003: the redundant plain index is gone, the UNIQUE index remains.
	indexCount := func(name string) int {
		var n int
		if err := db.QueryRow(`
			SELECT count(*) FROM pg_indexes
			WHERE schemaname = 'authkit' AND tablename = 'api_keys' AND indexname = $1
		`, name).Scan(&n); err != nil {
			t.Fatalf("query index %s: %v", name, err)
		}
		return n
	}
	if indexCount("idx_api_keys_key_hash") != 0 {
		t.Fatal("expected redundant idx_api_keys_key_hash to be dropped by 000003")
	}
	if indexCount("api_keys_key_hash_key") != 1 {
		t.Fatal("expected the UNIQUE key_hash index (api_keys_key_hash_key) to remain")
	}
}

// TestUpsertVerificationCodeAtomicRateLimit verifies the rate limit is enforced
// inside the upsert (no check-then-write TOCTOU): a second issuance within the
// window does not overwrite the active code (stored=false), while rateLimit<=0
// always stores.
func TestUpsertVerificationCodeAtomicRateLimit(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")

	repo := repository.New(db, db)
	tenantID := "otp.rl.test"
	createTenantAndUser(t, ctx, &repo, tenantID)

	req := model.CreateVerificationCodeRequest{
		TenantID:  tenantID,
		Email:     "u@" + tenantID,
		Code:      "111111",
		Purpose:   "signup",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	// First issuance: no existing code, always stores.
	stored, err := repo.UpsertVerificationCode(ctx, req, time.Minute)
	if err != nil || !stored {
		t.Fatalf("first upsert: stored=%v err=%v, want stored=true", stored, err)
	}

	// Second issuance within the window: the active code is too recent, so the
	// conditional update affects no rows — rate-limited, code unchanged.
	req2 := req
	req2.Code = "222222"
	stored, err = repo.UpsertVerificationCode(ctx, req2, time.Minute)
	if err != nil {
		t.Fatalf("second upsert err: %v", err)
	}
	if stored {
		t.Fatal("second upsert within window stored=true, want false (rate-limited)")
	}

	// rateLimit <= 0 disables the limit and always stores.
	stored, err = repo.UpsertVerificationCode(ctx, req2, 0)
	if err != nil || !stored {
		t.Fatalf("upsert with rateLimit=0: stored=%v err=%v, want stored=true", stored, err)
	}
}
