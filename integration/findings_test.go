//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/internal/service"
	"github.com/modgudinc/authkit-go/model"
)

// TestCreateUserDuplicateReturnsErrUserExists covers the user-creation half of
// the duplicate-email finding: in the decoupled model email is GLOBALLY unique (a
// lower(email) conflict), so a second global Create for the same email must surface
// model.ErrUserExists, not a raw Postgres unique-violation string.
func TestCreateUserDuplicateReturnsErrUserExists(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

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
		DisplayName:  "Duplicate",
	})
	if !errors.Is(err, model.ErrUserExists) {
		t.Fatalf("expected ErrUserExists on duplicate create, got %v", err)
	}

	// Case-insensitive: a different-cased spelling of the same email is the same
	// global identity and likewise conflicts (uniqueness is on lower(email)).
	if _, err := repo.Create(ctx, model.CreateUserRequest{
		Email:        "DUP@DUP.TEST",
		PasswordHash: hash,
		DisplayName:  "Duplicate Cased",
	}); !errors.Is(err, model.ErrUserExists) {
		t.Fatalf("expected ErrUserExists on case-insensitive duplicate, got %v", err)
	}
}

// TestAcceptInvitationReusesExistingIdentity is the decoupled-model conversion of the
// old "duplicate user on accept -> ErrUserExists" finding. That contract is GONE: with
// a global identity, accepting an invitation whose target email already has an account
// is NOT an error — the existing identity is REUSED (no second account/password) and
// simply granted the invited membership. This asserts the new behavior: Accept returns
// (existingUserID, created=false, nil), grants an active membership in the invitation's
// tenant with the invited roles, and consumes the single use.
func TestAcceptInvitationReusesExistingIdentity(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	pw := service.NewPasswordService(4, nil)
	ownerTenant := "invdup.test"
	ownerID := createTenantAndUserWithPassword(t, ctx, &repo, ownerTenant, "owner@invdup.test", "ValidPass1!", pw)

	// A GLOBAL identity already exists for the email the invitation will target (it is
	// a member of ownerTenant, created by the harness).
	email := "existing@invdup.test"
	existingID := createUserWithPassword(t, ctx, &repo, ownerTenant, email, "ValidPass1!", pw)

	// The invitation grants access to a DIFFERENT tenant, so the reuse adds a second
	// membership over the same identity (the headline decoupled behavior).
	inviteTenant := "invtarget.test"
	if err := repo.CreateTenant(ctx, model.CreateTenantRequest{
		TenantID:       inviteTenant,
		Name:           inviteTenant,
		AllowedDomains: []string{inviteTenant},
	}); err != nil {
		t.Fatalf("create invite tenant: %v", err)
	}

	code := "DUPINVITE00000000001"
	if err := repo.CreateInvitation(ctx, repository.InsertInvitationParams{
		Code:      code,
		TenantID:  inviteTenant,
		CreatedBy: ownerID,
		Roles:     []string{"Member"},
		Email:     email,
		ExpiresAt: time.Now().Add(time.Hour),
		MaxUses:   1,
	}); err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	gotID, created, err := repo.AcceptInvitation(ctx, code, email, "Existing User", "hashed-password")
	if err != nil {
		t.Fatalf("accept invitation for existing email should reuse the identity, got %v", err)
	}
	if created {
		t.Fatal("expected created=false: the existing global identity must be reused, not recreated")
	}
	if gotID != existingID {
		t.Fatalf("accept reused wrong identity: got %q, want existing %q", gotID, existingID)
	}

	// The reuse grants an active membership in the invitation's tenant with its roles.
	membership, err := repo.GetMembership(ctx, existingID, inviteTenant)
	if err != nil {
		t.Fatalf("get granted membership: %v", err)
	}
	if !membership.IsActive() || len(membership.Roles) != 1 || membership.Roles[0] != "Member" {
		t.Fatalf("granted membership unexpected: %+v", membership)
	}

	// The single use IS consumed (the accept succeeded).
	inv, err := repo.GetInvitation(ctx, code)
	if err != nil {
		t.Fatalf("get invitation after accept: %v", err)
	}
	if inv.CurrentUses != 1 {
		t.Fatalf("invitation should be consumed by a successful reuse-accept, current_uses=%d", inv.CurrentUses)
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
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)

	// Unknown token hash.
	if _, err := repo.GetByTokenHash(ctx, "no-such-token-hash"); !errors.Is(err, model.ErrInvalidRefreshToken) {
		t.Fatalf("unknown hash: expected ErrInvalidRefreshToken, got %v", err)
	}

	// Expired (but not revoked) token.
	tenantID := "rt.test"
	userID := createTenantAndUser(t, ctx, &repo, tenantID)
	if _, err := repo.CreateRefreshToken(ctx, repository.CreateRefreshTokenRequest{
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
// ValidateDomainAccess and GetByDomain.
func TestTenantDomainMatchingIsCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	authKit := newIntegrationAuthKit(t, db)
	tenantSvc := authKit.TenantService()
	tenantID := "case.test"

	created, err := tenantSvc.Create(ctx, model.CreateTenantRequest{
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
	got, err := tenantSvc.GetByDomain(ctx, "acme.com")
	if err != nil {
		t.Fatalf("get tenant by domain: %v", err)
	}
	if got.TenantID != tenantID {
		t.Fatalf("GetByDomain returned %q, want %q", got.TenantID, tenantID)
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
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	tenantID := "otpexp.test"
	createTenantAndUser(t, ctx, &repo, tenantID)
	email := "expired@" + tenantID

	if _, err := repo.UpsertVerificationCode(ctx, repository.CreateVerificationCodeRequest{
		Email:     email,
		CodeHash:  "123456",
		Purpose:   "signup",
		ExpiresAt: time.Now().Add(-time.Minute),
	}, 0); err != nil {
		t.Fatalf("upsert expired code: %v", err)
	}

	result, err := repo.ConsumeVerificationCode(ctx, email, "123456", "signup", 5)
	if err != nil {
		t.Fatalf("consume expired: %v", err)
	}
	if result != repository.OTPConsumeInvalid {
		t.Fatalf("expected OTPConsumeInvalid for expired code, got %v", result)
	}
	// The expired row must have been deleted by the consume path.
	if _, err := repo.GetVerificationCode(ctx, email, "signup"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("expected expired code to be deleted (ErrNotFound), got %v", err)
	}
}

// TestConsumeVerificationCodeRetainsLockedOutRow is the regression test for the
// finding that an attempt-lockout used to DELETE the code row, which reset the
// per-(tenant, email, purpose) generation cooldown so a burst of wrong guesses
// could drive unlimited OTP resends. The locked-out row must now be retained so
// its created_at keeps enforcing the rate limit.
func TestConsumeVerificationCodeRetainsLockedOutRow(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	tenantID := "otplock.test"
	createTenantAndUser(t, ctx, &repo, tenantID)
	email := "locked@" + tenantID
	const maxAttempts = 5
	cooldown := time.Hour // long enough that the limit is clearly still in force after lockout

	if _, err := repo.UpsertVerificationCode(ctx, repository.CreateVerificationCodeRequest{
		Email:     email,
		CodeHash:  "123456",
		Purpose:   "signup",
		ExpiresAt: time.Now().Add(time.Hour),
	}, cooldown); err != nil {
		t.Fatalf("upsert code: %v", err)
	}

	// Burn maxAttempts wrong guesses; the final one trips the lockout.
	for i := 0; i < maxAttempts; i++ {
		result, err := repo.ConsumeVerificationCode(ctx, email, "000000", "signup", maxAttempts)
		if err != nil {
			t.Fatalf("attempt %d: consume: %v", i+1, err)
		}
		want := repository.OTPConsumeInvalid
		if i == maxAttempts-1 {
			want = repository.OTPConsumeLockedOut
		}
		if result != want {
			t.Fatalf("attempt %d: result = %v, want %v", i+1, result, want)
		}
	}

	// The locked-out row must still exist (retained as a rate-limit tombstone).
	if _, err := repo.GetVerificationCode(ctx, email, "signup"); err != nil {
		t.Fatalf("expected locked-out code to be retained, got %v", err)
	}

	// And it must still enforce the generation cooldown: issuing a new code within
	// the window is refused (stored == false), proving the lockout did not reset it.
	stored, err := repo.UpsertVerificationCode(ctx, repository.CreateVerificationCodeRequest{
		Email:     email,
		CodeHash:  "654321",
		Purpose:   "signup",
		ExpiresAt: time.Now().Add(time.Hour),
	}, cooldown)
	if err != nil {
		t.Fatalf("re-upsert after lockout: %v", err)
	}
	if stored {
		t.Fatal("generation after lockout within cooldown must be rate-limited (stored=false)")
	}
}

// TestSingleSessionLogoutEnablesReuseDetection is the regression test for the
// finding that single-session logout used to hard-DELETE the refresh-token row, so
// replaying a stolen-then-logged-out token read as a benign ErrInvalidRefreshToken
// instead of tripping reuse/theft detection. Logout now soft-revokes (sets
// revoked_at) so a later replay is detected as reuse.
func TestSingleSessionLogoutEnablesReuseDetection(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	tenantID := "logoutreuse.test"
	userID := createTenantAndUser(t, ctx, &repo, tenantID)

	const tokenHash = "logout-reuse-hash" //nolint:gosec // G101 false positive: fixed test token-hash literal, not a credential
	if _, err := repo.CreateRefreshToken(ctx, repository.CreateRefreshTokenRequest{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	// Single-session logout soft-revokes the token (does not delete the row).
	if err := repo.RevokeByTokenHash(ctx, tokenHash); err != nil {
		t.Fatalf("revoke by token hash: %v", err)
	}

	// Replaying the logged-out token must be detected as reuse, not as a benign
	// invalid token — the retained, revoked row is what makes that possible.
	if _, _, err := repo.RotateRefreshToken(ctx, tokenHash, repository.CreateRefreshTokenRequest{ //nolint:gosec // G101 false positive: fixed test token-hash literal, not a credential
		UserID:    userID,
		TokenHash: "logout-reuse-replacement",
		ExpiresAt: time.Now().Add(time.Hour),
	}); !errors.Is(err, model.ErrRefreshTokenReuse) {
		t.Fatalf("replay of a logged-out token: expected ErrRefreshTokenReuse, got %v", err)
	}

	// Idempotent logout: revoking an already-revoked token reports not-found (which
	// the service layer treats as success), not an error.
	if err := repo.RevokeByTokenHash(ctx, tokenHash); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("re-revoking an already-revoked token: expected ErrNotFound, got %v", err)
	}
}

// TestSetPasswordAndBumpTokenVersion is the regression test for making the password
// write and the IDENTITY token_version bump atomic in ChangePassword: a single UPDATE
// must change both. A credential is now identity-level (global), so the write is keyed
// by user id only; an unknown user id matches no row and fails closed with ErrNotFound.
func TestSetPasswordAndBumpTokenVersion(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	tenantID := "pwbump.test"
	userID := createTenantAndUser(t, ctx, &repo, tenantID)

	before, err := repo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}

	if err := repo.SetPasswordAndBumpTokenVersion(ctx, userID, "new-hash-value"); err != nil {
		t.Fatalf("atomic password + token_version update: %v", err)
	}

	after, err := repo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if after.PasswordHash != "new-hash-value" {
		t.Fatalf("password_hash = %q, want updated value", after.PasswordHash)
	}
	if after.TokenVersion != before.TokenVersion+1 {
		t.Fatalf("token_version = %d, want %d (before+1)", after.TokenVersion, before.TokenVersion+1)
	}

	// Fail-closed: an unknown user id matches no row and changes nothing.
	missing := uuid.Must(uuid.NewV7()).String()
	if err := repo.SetPasswordAndBumpTokenVersion(ctx, missing, "attacker-hash"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("update of a missing user: expected ErrNotFound, got %v", err)
	}
	reloaded, err := repo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("reload after missing-user attempt: %v", err)
	}
	if reloaded.PasswordHash != "new-hash-value" || reloaded.TokenVersion != after.TokenVersion {
		t.Fatal("an unrelated missing-user update must not modify another identity's password or token_version")
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
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	tenantID := "ip.test"
	userID := createTenantAndUser(t, ctx, &repo, tenantID)

	ip, ua, dev := "127.0.0.1", "integration-agent", "test-device"
	if _, err := repo.CreateRefreshToken(ctx, repository.CreateRefreshTokenRequest{
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

// TestAPIKeyUUIDKeyIDRoundTripAndIndex covers two things on the api_keys table in
// the consolidated schema: that an API key with a UUID key_id inserts and reads
// back cleanly, and that key_hash is indexed only by its UNIQUE constraint (no
// separate, redundant idx_api_keys_key_hash).
func TestAPIKeyUUIDKeyIDRoundTripAndIndex(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

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

	// Only the UNIQUE index on key_hash exists (no redundant plain index).
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
		t.Fatal("expected no redundant idx_api_keys_key_hash (key_hash is UNIQUE-indexed)")
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
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	tenantID := "otp.rl.test"
	createTenantAndUser(t, ctx, &repo, tenantID)

	req := repository.CreateVerificationCodeRequest{
		Email:     "u@" + tenantID,
		CodeHash:  "111111",
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
	req2.CodeHash = "222222"
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

// TestUserStatusAuditWrittenInGo verifies the consolidated schema's end state and
// that the repository writes user_status_changes rows in Go (no DB trigger):
// exactly one row per real transition, with Go-minted UUID ids and the
// status_type / changed_by_type / metadata the former trigger used.
func TestUserStatusAuditWrittenInGo(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	// Consolidated schema: no SQL-side UUID generation, no trigger, no auth_events.
	mustBeTrue := func(what, q string, args ...any) {
		var ok bool
		if err := db.QueryRow(q, args...).Scan(&ok); err != nil {
			t.Fatalf("query %s: %v", what, err)
		}
		if !ok {
			t.Fatalf("expected %s", what)
		}
	}
	mustBeTrue("auth_events dropped", `SELECT NOT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema='authkit' AND table_name='auth_events')`)
	mustBeTrue("uuid_generate_v7 dropped", `SELECT NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='authkit' AND p.proname='uuid_generate_v7')`)
	mustBeTrue("status trigger dropped", `SELECT NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='track_user_status_changes' AND NOT tgisinternal)`)
	mustBeTrue("users.id has no default", `SELECT column_default IS NULL FROM information_schema.columns WHERE table_schema='authkit' AND table_name='users' AND column_name='id'`)
	mustBeTrue("user_status_changes kept", `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema='authkit' AND table_name='user_status_changes')`)

	repo := repository.New(db, db)
	tenantID := "audit.test"
	userID := createTenantAndUser(t, ctx, &repo, tenantID)

	type change struct {
		id, statusType, changedByType, prev, next string
		changedByNull                             bool
	}
	listChanges := func() []change {
		rows, err := db.Query(`
			SELECT id::text, status_type, changed_by_type, changed_by IS NULL,
			       metadata->>'previous_state', metadata->>'new_state'
			FROM authkit.user_status_changes WHERE user_id = $1 ORDER BY changed_at`, userID)
		if err != nil {
			t.Fatalf("list status changes: %v", err)
		}
		defer func() { _ = rows.Close() }()
		var out []change
		for rows.Next() {
			var c change
			if err := rows.Scan(&c.id, &c.statusType, &c.changedByType, &c.changedByNull, &c.prev, &c.next); err != nil {
				t.Fatalf("scan status change: %v", err)
			}
			out = append(out, c)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate status changes: %v", err)
		}
		return out
	}

	// Disable: exactly one 'disable'/'admin' row with a Go-minted UUID id and the
	// trigger's metadata shape.
	if err := repo.Disable(ctx, userID); err != nil {
		t.Fatalf("disable: %v", err)
	}
	changes := listChanges()
	if len(changes) != 1 {
		t.Fatalf("after disable: %d audit rows, want 1", len(changes))
	}
	c := changes[0]
	if c.statusType != "disable" || c.changedByType != "admin" || !c.changedByNull || c.prev != "true" || c.next != "false" {
		t.Fatalf("disable audit row = %+v", c)
	}
	if _, err := uuid.Parse(c.id); err != nil {
		t.Fatalf("audit id %q is not a UUID: %v", c.id, err)
	}

	// Disabling an already-disabled user is a no-op transition: no new row.
	if err := repo.Disable(ctx, userID); err != nil {
		t.Fatalf("re-disable: %v", err)
	}
	if got := len(listChanges()); got != 1 {
		t.Fatalf("re-disabling an already-disabled user added rows: %d, want 1", got)
	}

	// Admin lock (low failed-login count) is attributed to 'admin'.
	if err := repo.Lock(ctx, userID, nil); err != nil {
		t.Fatalf("lock: %v", err)
	}
	changes = listChanges()
	if len(changes) != 2 || changes[1].statusType != "lock" || changes[1].changedByType != "admin" {
		t.Fatalf("after admin lock, changes = %+v", changes)
	}
}

// TestRegisterFailedLoginAuditsSystemLock verifies the failed-login lockout path
// records a single 'lock' row attributed to 'system' when the threshold is hit.
func TestRegisterFailedLoginAuditsSystemLock(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	tenantID := "lock.test"
	userID := createTenantAndUser(t, ctx, &repo, tenantID)

	// First four failures stay under the threshold: no lock, no audit row.
	for i := 0; i < 4; i++ {
		_, locked, err := repo.RegisterFailedLogin(ctx, userID, 5, time.Minute)
		if err != nil || locked {
			t.Fatalf("attempt %d: locked=%v err=%v, want not locked", i+1, locked, err)
		}
	}
	// Fifth failure crosses the threshold and locks.
	count, locked, err := repo.RegisterFailedLogin(ctx, userID, 5, time.Minute)
	if err != nil || !locked || count != 5 {
		t.Fatalf("fifth attempt: count=%d locked=%v err=%v, want count=5 locked=true", count, locked, err)
	}

	var n int
	var statusType, changedByType string
	if err := db.QueryRow(`
		SELECT count(*), coalesce(max(status_type), ''), coalesce(max(changed_by_type), '')
		FROM authkit.user_status_changes WHERE user_id = $1`, userID).Scan(&n, &statusType, &changedByType); err != nil {
		t.Fatalf("query status changes: %v", err)
	}
	if n != 1 || statusType != "lock" || changedByType != "system" {
		t.Fatalf("got %d rows, status=%q changed_by_type=%q; want 1 lock/system", n, statusType, changedByType)
	}
}

// TestAdminLockIsAdminAttributedAndKeepsFailedCount verifies the explicit admin
// Lock path is attributed to 'admin' (never inferred to 'system' from the failed
// count) and does not touch failed_login_count, matching LockByTenant.
func TestAdminLockIsAdminAttributedAndKeepsFailedCount(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	tenantID := "adminlock.test"
	userID := createTenantAndUser(t, ctx, &repo, tenantID)

	// Pre-load a non-trivial failed-login count that already sits at/above the
	// auto-lock threshold; the old code would have inferred this admin lock as
	// 'system'. The explicit provenance must keep it 'admin'.
	if _, err := db.Exec(`UPDATE authkit.users SET failed_login_count = 4 WHERE id = $1`, userID); err != nil {
		t.Fatalf("seed failed_login_count: %v", err)
	}

	if err := repo.Lock(ctx, userID, nil); err != nil {
		t.Fatalf("admin lock: %v", err)
	}

	var changedByType string
	var failedCount int
	if err := db.QueryRow(`
		SELECT changed_by_type FROM authkit.user_status_changes
		WHERE user_id = $1 AND status_type = 'lock'`, userID).Scan(&changedByType); err != nil {
		t.Fatalf("read lock audit row: %v", err)
	}
	if changedByType != "admin" {
		t.Fatalf("admin lock attributed to %q, want admin", changedByType)
	}
	if err := db.QueryRow(`SELECT failed_login_count FROM authkit.users WHERE id = $1`, userID).Scan(&failedCount); err != nil {
		t.Fatalf("read failed_login_count: %v", err)
	}
	if failedCount != 4 {
		t.Fatalf("admin Lock changed failed_login_count to %d, want it left at 4", failedCount)
	}
}

// TestNotFoundMutatorsWrapErrNotFound verifies the id/name-scoped mutators that
// previously returned bare strings now wrap model.ErrNotFound, so callers can map
// a missing row to a 404 with errors.Is.
func TestNotFoundMutatorsWrapErrNotFound(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	missingUser := uuid.Must(uuid.NewV7()).String()

	newName := "x"
	cases := map[string]error{
		"Update":       repo.Update(ctx, missingUser, model.UpdateUserRequest{DisplayName: &newName}),
		"UpdateName":   repo.UpdateName(ctx, "no-such-tenant", "x"),
		"DeleteAPIKey": repo.DeleteAPIKey(ctx, uuid.Must(uuid.NewV7()).String(), "no-such-tenant"),
		"Delete":       repo.DeleteSecret(ctx, "no-such-tenant", "no-such-key"),
		"DeleteInvite": repo.DeleteInvitation(ctx, "NOSUCHCODE"),
	}
	for name, err := range cases {
		if !errors.Is(err, model.ErrNotFound) {
			t.Fatalf("%s on a missing record: got %v, want wrap of ErrNotFound", name, err)
		}
	}
}

// TestValidateInvitationKnownInvalidIsFalseNil verifies the corrected contract:
// an unknown or exhausted invitation is a normal "not usable" outcome returned as
// (false, nil), not a (false, error) that a caller would misread as a fault.
func TestValidateInvitationKnownInvalidIsFalseNil(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	tenantID := "invite.test"
	createdBy := createTenantAndUser(t, ctx, &repo, tenantID)
	svc := service.NewInvitationService(&repo, nil)

	// Unknown code: not usable, not a fault.
	if valid, err := svc.Validate(ctx, "DOESNOTEXISTCODE0001"); valid || err != nil {
		t.Fatalf("unknown code: got (valid=%v, err=%v), want (false, nil)", valid, err)
	}

	// Exhausted code (single-use, already consumed): not usable, not a fault. (A
	// past expiry can't be seeded — a CHECK constraint requires expires_at >
	// created_at — so exhaustion exercises the same ErrInvitationInvalid branch.)
	const code = "EXHAUSTEDCODE0000001"
	if err := repo.CreateInvitation(ctx, repository.InsertInvitationParams{
		Code:      code,
		TenantID:  tenantID,
		CreatedBy: createdBy,
		Roles:     []string{"member"},
		Email:     "invitee@" + tenantID,
		ExpiresAt: time.Now().Add(time.Hour),
		MaxUses:   1,
	}); err != nil {
		t.Fatalf("seed invitation: %v", err)
	}
	if err := repo.IncrementUseCount(ctx, code); err != nil {
		t.Fatalf("exhaust invitation: %v", err)
	}
	if valid, err := svc.Validate(ctx, code); valid || err != nil {
		t.Fatalf("exhausted code: got (valid=%v, err=%v), want (false, nil)", valid, err)
	}
}

// TestCreateAPIKeyExpiresInDuration covers the service-level Create path
// with ExpiresIn now a *time.Duration: a provided duration yields ExpiresAt ≈
// now+duration, and a nil duration yields a never-expiring key (nil ExpiresAt).
func TestCreateAPIKeyExpiresInDuration(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	tenantID := "apikey.dur.test"
	createdBy := createTenantAndUser(t, ctx, &repo, tenantID)
	svc := service.NewAPIKeyService(&repo, "test-api-key-hmac-secret-0123456789", nil)

	ttl := 48 * time.Hour
	resp, err := svc.Create(ctx, model.CreateAPIKeyRequest{
		TenantID: tenantID, CreatedBy: createdBy, Name: "dur-key", ExpiresIn: &ttl,
	})
	if err != nil {
		t.Fatalf("create api key with duration: %v", err)
	}
	if resp.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be set when ExpiresIn is provided")
	}
	if diff := time.Until(*resp.ExpiresAt) - ttl; diff > time.Minute || diff < -time.Minute {
		t.Fatalf("ExpiresAt is %s away, want ~%s", time.Until(*resp.ExpiresAt), ttl)
	}

	resp2, err := svc.Create(ctx, model.CreateAPIKeyRequest{
		TenantID: tenantID, CreatedBy: createdBy, Name: "no-exp-key",
	})
	if err != nil {
		t.Fatalf("create api key without expiry: %v", err)
	}
	if resp2.ExpiresAt != nil {
		t.Fatalf("expected nil ExpiresAt for no expiry, got %s", resp2.ExpiresAt)
	}
}

// TestPartialUpdateAndMembershipRoles is the decoupled-model conversion of the old
// "UpdateByTenant partial update" coverage. The user is now a global identity whose
// display-name edit (repo.Update, keyed by user id) must NOT touch the identity
// token_version; roles moved off the user onto the membership, where a role change
// (UpdateMembershipRoles) bumps the MEMBERSHIP token_version (only this workspace's
// access tokens) and leaves the identity token_version alone.
func TestPartialUpdateAndMembershipRoles(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	tenantID := "partial.update.test"
	userID := createTenantAndUser(t, ctx, &repo, tenantID)

	before, err := repo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("get before: %v", err)
	}
	mBefore, err := repo.GetMembership(ctx, userID, tenantID)
	if err != nil {
		t.Fatalf("get membership before: %v", err)
	}

	// Display-name update on the global identity: identity token_version untouched (a
	// display-name edit must not invalidate sessions).
	newName := "Renamed User"
	if err := repo.Update(ctx, userID, model.UpdateUserRequest{DisplayName: &newName}); err != nil {
		t.Fatalf("name update: %v", err)
	}
	afterName, err := repo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("get after name: %v", err)
	}
	if afterName.DisplayName != newName {
		t.Fatalf("display name = %q, want %q", afterName.DisplayName, newName)
	}
	if afterName.TokenVersion != before.TokenVersion {
		t.Fatalf("identity token_version bumped on name update: %d -> %d", before.TokenVersion, afterName.TokenVersion)
	}

	// Roles now live on the membership. A role change bumps the MEMBERSHIP
	// token_version and leaves the identity token_version untouched.
	newRoles := []string{"Viewer"}
	if err := repo.UpdateMembershipRoles(ctx, userID, tenantID, newRoles); err != nil {
		t.Fatalf("update membership roles: %v", err)
	}
	mAfter, err := repo.GetMembership(ctx, userID, tenantID)
	if err != nil {
		t.Fatalf("get membership after roles: %v", err)
	}
	if !slices.Equal(mAfter.Roles, newRoles) {
		t.Fatalf("membership roles = %v, want %v", mAfter.Roles, newRoles)
	}
	if mAfter.TokenVersion != mBefore.TokenVersion+1 {
		t.Fatalf("membership token_version not bumped on roles change: %d -> %d", mBefore.TokenVersion, mAfter.TokenVersion)
	}
	// The identity token_version is unaffected by a per-workspace role change.
	afterRoles, err := repo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("get identity after roles: %v", err)
	}
	if afterRoles.TokenVersion != before.TokenVersion {
		t.Fatalf("identity token_version changed on membership role update: %d -> %d", before.TokenVersion, afterRoles.TokenVersion)
	}
	if afterRoles.DisplayName != newName {
		t.Fatalf("display name changed on membership role update: %q", afterRoles.DisplayName)
	}
}

// TestMembershipGatesWorkspaceAccess is the decoupled-model conversion of the old
// "cross-tenant user operations are rejected" finding. In the decoupled model the user
// is a single GLOBAL identity, so per-user operations (ChangePassword, LogoutAll,
// VerifyPassword, ...) are NOT tenant-scoped — they act on the one identity. The
// tenant-isolation guarantee MOVED to the membership graph: authentication is global,
// but AUTHORIZATION to a workspace is the active membership. This test encodes that
// converted invariant with the same strength:
//   - valid credentials but NO active membership in a tenant cannot obtain a token for
//     it (Login / LoginByEmail / MintWorkspaceToken / RefreshToken -> ErrNoActiveMembership);
//   - suspending the membership immediately revokes that workspace's access tokens
//     (ValidateJWT -> ErrTokenRevoked) and refresh into it (-> ErrNoActiveMembership),
//     WITHOUT touching the identity session (the user still authenticates and other
//     workspaces are unaffected);
//   - the identity-level self-service ops still work globally (positive controls).
func TestMembershipGatesWorkspaceAccess(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	repo := repository.New(db, db)
	pw := service.NewPasswordService(4, nil)

	const (
		tenantA  = "tenant-a.xtest" // the identity is an active member here
		tenantB  = "tenant-b.xtest" // ... but NOT a member here
		password = "ValidPass1!"
	)
	email := "alice@" + tenantA
	userID := createTenantAndUserWithPassword(t, ctx, &repo, tenantA, email, password, pw)
	// tenantB exists but the identity has no membership in it.
	if err := repo.CreateTenant(ctx, model.CreateTenantRequest{
		TenantID:       tenantB,
		Name:           tenantB,
		AllowedDomains: []string{tenantB},
	}); err != nil {
		t.Fatalf("create tenant B: %v", err)
	}

	authKit := newIntegrationAuthKit(t, db)
	authSvc := authKit.AuthService()
	userSvc := authKit.UserService()

	// --- No membership in tenantB: valid creds cannot obtain a tenantB token. ---
	if _, err := authSvc.Login(ctx, model.LoginRequest{Email: email, Password: password, TenantID: tenantB}); !errors.Is(err, model.ErrNoActiveMembership) {
		t.Fatalf("login into a non-member workspace: expected ErrNoActiveMembership, got %v", err)
	}
	if _, err := authSvc.LoginByEmail(ctx, model.LoginByEmailRequest{Email: email, Password: password, TenantID: tenantB}); !errors.Is(err, model.ErrNoActiveMembership) {
		t.Fatalf("login-by-email into a non-member workspace: expected ErrNoActiveMembership, got %v", err)
	}

	// Active member of tenantA: login succeeds and the token validates.
	login, err := authSvc.Login(ctx, model.LoginRequest{Email: email, Password: password, TenantID: tenantA})
	if err != nil {
		t.Fatalf("victim login into tenantA: %v", err)
	}
	if _, err := authSvc.ValidateJWT(ctx, login.AccessToken); err != nil {
		t.Fatalf("tenantA access token should validate: %v", err)
	}
	// The identity session cannot mint a token for a workspace it does not belong to.
	if _, err := authSvc.MintWorkspaceToken(ctx, login.RefreshToken, tenantB); !errors.Is(err, model.ErrNoActiveMembership) {
		t.Fatalf("mint token for non-member workspace: expected ErrNoActiveMembership, got %v", err)
	}

	// --- Suspend the tenantA membership: that workspace's tokens are revoked, but the
	// identity session itself is NOT (the credentials still authenticate). ---
	if err := repo.RemoveMembership(ctx, userID, tenantA); err != nil {
		t.Fatalf("suspend membership: %v", err)
	}
	if _, err := authSvc.ValidateJWT(ctx, login.AccessToken); !errors.Is(err, model.ErrTokenRevoked) {
		t.Fatalf("after membership suspend, ValidateJWT: expected ErrTokenRevoked, got %v", err)
	}
	if _, err := authSvc.RefreshToken(ctx, model.RefreshRequest{RefreshToken: login.RefreshToken, TenantID: tenantA}); !errors.Is(err, model.ErrNoActiveMembership) {
		t.Fatalf("refresh into a suspended workspace: expected ErrNoActiveMembership, got %v", err)
	}
	// The identity is intact: it can still authenticate (login fails only on the
	// workspace gate, not the credential), proving suspend did not kill the identity.
	if _, err := authSvc.LoginByEmail(ctx, model.LoginByEmailRequest{Email: email, Password: password}); err != nil {
		t.Fatalf("identity must still authenticate after a workspace suspend: %v", err)
	}

	// --- Identity-level self-service ops act on the one global identity (positive
	// controls; they are no longer tenant-scoped). ---
	if _, err := userSvc.VerifyPassword(ctx, userID); err != nil {
		t.Fatalf("identity VerifyPassword should succeed: %v", err)
	}
	if name, err := userSvc.GetDisplayName(ctx, userID); err != nil || name == "" {
		t.Fatalf("identity GetDisplayName should succeed, got name=%q err=%v", name, err)
	}
	if err := authSvc.ChangePassword(ctx, model.ChangePasswordRequest{
		UserID:      userID,
		OldPassword: password,
		NewPassword: "NewValidPass1!",
	}); err != nil {
		t.Fatalf("identity ChangePassword should succeed: %v", err)
	}
	// ChangePassword revokes sessions identity-wide: the original refresh token dies.
	if _, err := authSvc.RefreshToken(ctx, model.RefreshRequest{RefreshToken: login.RefreshToken, TenantID: tenantA}); err == nil {
		t.Fatal("expected the original refresh token to be invalid after identity password change")
	}
	// LogoutAll is identity-level (no tenant) and fails closed for an unknown id.
	if err := authSvc.LogoutAll(ctx, userID); err != nil {
		t.Fatalf("identity LogoutAll should succeed: %v", err)
	}
	missing := uuid.Must(uuid.NewV7()).String()
	if err := authSvc.LogoutAll(ctx, missing); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("LogoutAll for unknown id should fail closed with ErrNotFound, got %v", err)
	}
}
