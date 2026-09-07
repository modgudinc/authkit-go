//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	authkit "github.com/modgudinc/authkit-go"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/internal/service"
	"github.com/modgudinc/authkit-go/model"
)

const defaultDatabaseURL = "postgres://authkit_test:authkit_test@localhost:55432/authkit_test?sslmode=disable"

func TestMigrationsAlignWithRepository(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() { _ = db.Close() }()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")
	assertTablesExist(t, db)

	repo := repository.New(db, db)
	tenantID := "acme.test"
	userID := createTenantAndUser(t, ctx, &repo, tenantID)

	testRefreshTokenRotation(t, ctx, &repo, userID)
	testAPIKeyPersistence(t, ctx, &repo, tenantID, userID)
	testOTPPersistence(t, ctx, &repo, tenantID)
	testInvitationPersistence(t, ctx, &repo, tenantID, userID)
	testInvitationAccept(t, ctx, &repo, tenantID, userID)
	testRoleUpdateBumpsTokenVersion(t, ctx, &repo, tenantID, userID)
	testSecretPersistence(t, ctx, &repo, tenantID, userID)
}

// TestDecoupledSchemaStructure asserts the decoupled-identity schema shape directly
// against information_schema / pg_catalog. It is the structural counterpart to the
// old tenant-scoped-user assertions, converted to the new contract:
//   - users is a GLOBAL identity: no tenant_id and no roles columns.
//   - email uniqueness is GLOBAL and case-insensitive: a UNIQUE index on lower(email)
//     (users_email_lower_unique), not a per-tenant (tenant_id, email) unique.
//   - the new memberships table is the user<->tenant graph: PK (user_id, tenant_id),
//     a roles jsonb column, a token_version, a status CHECK in (active, suspended),
//     and FKs to users/tenants that CASCADE on delete.
//   - verification_codes is keyed by (email, purpose) with no tenant_id column.
func TestDecoupledSchemaStructure(t *testing.T) {
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")

	columnExists := func(table, column string) bool {
		var ok bool
		if err := db.QueryRow(`
			SELECT EXISTS(
				SELECT 1 FROM information_schema.columns
				WHERE table_schema='authkit' AND table_name=$1 AND column_name=$2
			)`, table, column).Scan(&ok); err != nil {
			t.Fatalf("check column %s.%s: %v", table, column, err)
		}
		return ok
	}

	// --- users: global identity, no tenant_id / roles. ---
	if columnExists("users", "tenant_id") {
		t.Fatal("users.tenant_id must not exist: users is a global identity")
	}
	if columnExists("users", "roles") {
		t.Fatal("users.roles must not exist: roles live on memberships")
	}
	if !columnExists("users", "token_version") {
		t.Fatal("users.token_version (identity token version) must exist")
	}

	// --- Global, case-insensitive email uniqueness on lower(email). ---
	var emailUniqueDef string
	if err := db.QueryRow(`
		SELECT indexdef FROM pg_indexes
		WHERE schemaname='authkit' AND tablename='users' AND indexname='users_email_lower_unique'
	`).Scan(&emailUniqueDef); err != nil {
		t.Fatalf("expected users_email_lower_unique index: %v", err)
	}
	// Postgres normalizes the expression to lower((email)::text), so match on the
	// lower(...) call over the email column rather than an exact spelling.
	lowerDef := strings.ToLower(emailUniqueDef)
	if !strings.Contains(emailUniqueDef, "UNIQUE") || !strings.Contains(lowerDef, "lower(") || !strings.Contains(lowerDef, "email") {
		t.Fatalf("users_email_lower_unique is not a UNIQUE index on lower(email): %q", emailUniqueDef)
	}
	// No legacy per-tenant (tenant_id, email) uniqueness survives.
	var legacyTenantEmailUnique bool
	if err := db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM pg_indexes
			WHERE schemaname='authkit' AND tablename='users'
			  AND indexdef ILIKE '%tenant_id%' AND indexdef ILIKE '%email%'
		)`).Scan(&legacyTenantEmailUnique); err != nil {
		t.Fatalf("check legacy tenant-email index: %v", err)
	}
	if legacyTenantEmailUnique {
		t.Fatal("a legacy (tenant_id, email) index must not exist on the decoupled users table")
	}

	// --- memberships: the user<->tenant graph. ---
	for _, col := range []string{"user_id", "tenant_id", "roles", "token_version", "status"} {
		if !columnExists("memberships", col) {
			t.Fatalf("memberships.%s must exist", col)
		}
	}
	// roles is jsonb.
	var rolesType string
	if err := db.QueryRow(`
		SELECT data_type FROM information_schema.columns
		WHERE table_schema='authkit' AND table_name='memberships' AND column_name='roles'
	`).Scan(&rolesType); err != nil {
		t.Fatalf("read memberships.roles type: %v", err)
	}
	if rolesType != "jsonb" {
		t.Fatalf("memberships.roles type = %q, want jsonb", rolesType)
	}
	// PK is exactly (user_id, tenant_id).
	pkCols := func(table string) []string {
		rows, err := db.Query(`
			SELECT a.attname
			FROM pg_index i
			JOIN pg_class c ON c.oid = i.indrelid
			JOIN pg_namespace n ON n.oid = c.relnamespace
			JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
			WHERE n.nspname='authkit' AND c.relname=$1 AND i.indisprimary
			ORDER BY array_position(i.indkey, a.attnum)`, table)
		if err != nil {
			t.Fatalf("read pk cols for %s: %v", table, err)
		}
		defer func() { _ = rows.Close() }()
		var cols []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatalf("scan pk col: %v", err)
			}
			cols = append(cols, c)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate pk cols: %v", err)
		}
		return cols
	}
	if got := pkCols("memberships"); len(got) != 2 || got[0] != "user_id" || got[1] != "tenant_id" {
		t.Fatalf("memberships PK = %v, want [user_id tenant_id]", got)
	}
	// status CHECK constrains to active|suspended.
	var statusCheck string
	if err := db.QueryRow(`
		SELECT pg_get_constraintdef(con.oid)
		FROM pg_constraint con
		JOIN pg_class c ON c.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname='authkit' AND c.relname='memberships'
		  AND con.contype='c' AND pg_get_constraintdef(con.oid) ILIKE '%status%'
	`).Scan(&statusCheck); err != nil {
		t.Fatalf("read memberships status check: %v", err)
	}
	if !strings.Contains(statusCheck, "active") || !strings.Contains(statusCheck, "suspended") {
		t.Fatalf("memberships status CHECK = %q, want active|suspended", statusCheck)
	}
	// Both FKs (to users and tenants) cascade on delete.
	fkCascades := func(refTable string) bool {
		var ok bool
		if err := db.QueryRow(`
			SELECT EXISTS(
				SELECT 1
				FROM pg_constraint con
				JOIN pg_class c ON c.oid = con.conrelid
				JOIN pg_namespace n ON n.oid = c.relnamespace
				JOIN pg_class rc ON rc.oid = con.confrelid
				WHERE n.nspname='authkit' AND c.relname='memberships'
				  AND con.contype='f' AND rc.relname=$1 AND con.confdeltype='c'
			)`, refTable).Scan(&ok); err != nil {
			t.Fatalf("check membership FK to %s: %v", refTable, err)
		}
		return ok
	}
	if !fkCascades("users") {
		t.Fatal("memberships.user_id must FK to users ON DELETE CASCADE")
	}
	if !fkCascades("tenants") {
		t.Fatal("memberships.tenant_id must FK to tenants ON DELETE CASCADE")
	}

	// --- verification_codes keyed by (email, purpose), no tenant_id. ---
	if columnExists("verification_codes", "tenant_id") {
		t.Fatal("verification_codes.tenant_id must not exist: OTP is keyed by (email, purpose) globally")
	}
	if got := pkCols("verification_codes"); len(got) != 2 || got[0] != "email" || got[1] != "purpose" {
		t.Fatalf("verification_codes PK = %v, want [email purpose]", got)
	}
}

func TestAuthServiceFlows(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")

	repo := repository.New(db, db)
	passwordService := service.NewPasswordService(4, nil)
	tenantID := "auth.test"
	loginUserID := createTenantAndUserWithPassword(t, ctx, &repo, tenantID, "login@auth.test", "ValidPass1!", passwordService)

	authKit := newIntegrationAuthKit(t, db)
	authService := authKit.AuthService()

	login, err := authService.Login(ctx, model.LoginRequest{
		Email:    "login@auth.test",
		Password: "ValidPass1!",
		TenantID: tenantID,
		SessionInfo: &model.SessionInfo{
			IPAddress:  "127.0.0.1",
			UserAgent:  "integration-test",
			DeviceName: "test-device",
		},
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if login.User.ID != loginUserID || login.AccessToken == "" || login.RefreshToken == "" {
		t.Fatalf("unexpected login response: %+v", login)
	}

	if _, err := authService.ValidateJWT(ctx, login.AccessToken); err != nil {
		t.Fatalf("validate login jwt: %v", err)
	}

	refreshed, err := authService.RefreshToken(ctx, model.RefreshRequest{RefreshToken: login.RefreshToken, TenantID: tenantID})
	if err != nil {
		t.Fatalf("refresh token: %v", err)
	}
	if refreshed.UserID != loginUserID || refreshed.RefreshToken == "" || refreshed.RefreshToken == login.RefreshToken {
		t.Fatalf("unexpected refresh response: %+v", refreshed)
	}
	if refreshed.TenantID != tenantID {
		t.Fatalf("refreshed token scoped to %q, want %q", refreshed.TenantID, tenantID)
	}

	if _, err := authService.RefreshToken(ctx, model.RefreshRequest{RefreshToken: login.RefreshToken, TenantID: tenantID}); err == nil {
		t.Fatal("expected old refresh token to fail after rotation")
	}

	if err := authService.Logout(ctx, refreshed.RefreshToken); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := authService.RefreshToken(ctx, model.RefreshRequest{RefreshToken: refreshed.RefreshToken, TenantID: tenantID}); err == nil {
		t.Fatal("expected logged-out refresh token to fail")
	}

	secondLogin, err := authService.Login(ctx, model.LoginRequest{
		Email:    "login@auth.test",
		Password: "ValidPass1!",
		TenantID: tenantID,
	})
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	// LogoutAll is now identity-level (no tenant): it bumps the identity token_version
	// and revokes every refresh token across all of the identity's workspaces.
	if err := authService.LogoutAll(ctx, loginUserID); err != nil {
		t.Fatalf("logout all: %v", err)
	}
	if _, err := authService.ValidateJWT(ctx, secondLogin.AccessToken); err == nil {
		t.Fatal("expected access token to fail after logout all increments token version")
	}
	if _, err := authService.RefreshToken(ctx, model.RefreshRequest{RefreshToken: secondLogin.RefreshToken, TenantID: tenantID}); err == nil {
		t.Fatal("expected refresh token to fail after logout all")
	}

	lockoutUserID := createUserWithPassword(t, ctx, &repo, tenantID, "lockout@auth.test", "ValidPass1!", passwordService)
	for i := 0; i < service.MaxFailedLoginAttempts; i++ {
		_, err := authService.Login(ctx, model.LoginRequest{
			Email:    "lockout@auth.test",
			Password: "WrongPass1!",
			TenantID: tenantID,
		})
		if err == nil {
			t.Fatalf("wrong password attempt %d unexpectedly succeeded", i+1)
		}
	}

	lockedUser, err := repo.GetByID(ctx, lockoutUserID)
	if err != nil {
		t.Fatalf("get locked user: %v", err)
	}
	if !lockedUser.IsLocked || lockedUser.FailedLoginCount < service.MaxFailedLoginAttempts {
		t.Fatalf("user was not locked after failed attempts: %+v", lockedUser)
	}
	if _, err := authService.Login(ctx, model.LoginRequest{
		Email:    "lockout@auth.test",
		Password: "ValidPass1!",
		TenantID: tenantID,
	}); err == nil {
		t.Fatal("expected locked account login to fail even with correct password")
	}
}

// TestCustomSchemaAndGlobalIdentityAcrossTenants exercises the custom-schema wiring
// AND the decoupled-identity model's headline behavioral change. The pre-migration
// test asserted the OPPOSITE invariant ("the same email in two tenants is two
// distinct users", tenant-scoped email uniqueness); that is no longer the contract.
// Converted to the decoupled equivalent: an email is ONE global identity, and
// belonging to two tenants is two membership rows over that single identity. A second
// global Create for the same email is a global-uniqueness conflict (ErrUserExists);
// access to each tenant is granted via AddMembership.
func TestCustomSchemaAndGlobalIdentityAcrossTenants(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		_, _ = db.Exec(`DROP SCHEMA IF EXISTS custom_identity CASCADE`)
		_ = db.Close()
	}()

	applyCustomSchemaMigration(t, db, "custom_identity")
	assertTablesExistInSchema(t, db, "custom_identity")

	repo := repository.NewWithSchema(db, db, "custom_identity")
	passwordService := service.NewPasswordService(4, nil)

	const sharedEmail = "shared@example.test"

	// tenant-a: tenant + global identity + active membership.
	userA := createTenantAndUserWithPassword(t, ctx, &repo, "tenant-a.test", sharedEmail, "ValidPass1!", passwordService)

	// tenant-b: just the tenant. The same email is the SAME global identity, so a
	// second global Create must conflict rather than mint a second user.
	if err := repo.CreateTenant(ctx, model.CreateTenantRequest{
		TenantID:       "tenant-b.test",
		Name:           "tenant-b.test",
		AllowedDomains: []string{"tenant-b.test"},
	}); err != nil {
		t.Fatalf("create tenant-b: %v", err)
	}
	hash, err := passwordService.HashPassword("ValidPass1!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := repo.Create(ctx, model.CreateUserRequest{
		Email:        sharedEmail,
		PasswordHash: hash,
		DisplayName:  "Second",
	}); !errors.Is(err, model.ErrUserExists) {
		t.Fatalf("second global Create for same email: expected ErrUserExists, got %v", err)
	}

	// Belonging to tenant-b is a second membership over the one global identity.
	grantMembership(t, ctx, &repo, userA, "tenant-b.test", []string{"Member"})

	// The email resolves to exactly one global identity (no tenant arg anymore).
	got, err := repo.GetByEmail(ctx, sharedEmail)
	if err != nil {
		t.Fatalf("get global user by email: %v", err)
	}
	if got.ID != userA {
		t.Fatalf("global lookup returned %q, want the single identity %q", got.ID, userA)
	}

	// One identity, two active memberships (tenant-a from the harness, tenant-b just
	// granted) — the decoupled equivalent of the old "two users".
	mships, err := repo.ListMembershipsByUser(ctx, userA)
	if err != nil {
		t.Fatalf("list memberships: %v", err)
	}
	tenants := map[string]bool{}
	for _, m := range mships {
		if m.IsActive() {
			tenants[m.TenantID] = true
		}
	}
	if !tenants["tenant-a.test"] || !tenants["tenant-b.test"] {
		t.Fatalf("expected active memberships in both tenants, got %v", tenants)
	}
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := os.Getenv("IDENTITY_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = defaultDatabaseURL
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}

	deadline := time.Now().Add(20 * time.Second)
	for {
		if err := db.Ping(); err == nil {
			return db
		}
		if time.Now().After(deadline) {
			t.Fatalf("database did not become ready at %s", dsn)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func applyMigration(t *testing.T, db *sql.DB, name string) {
	t.Helper()

	path := filepath.Join("..", "migrations", name)
	sqlBytes, err := os.ReadFile(path) //nolint:gosec // G304: test reads migration SQL from the repo's fixed migrations dir
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	if _, err := db.Exec(string(sqlBytes)); err != nil {
		t.Fatalf("apply migration %s: %v", name, err)
	}
}

func applyCustomSchemaMigration(t *testing.T, db *sql.DB, schema string) {
	t.Helper()

	_, _ = db.Exec(`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`)

	path := filepath.Join("..", "migrations", "000001_identity_schema.up.sql")
	sqlBytes, err := os.ReadFile(path) //nolint:gosec // G304: test reads migration SQL from the repo's fixed migrations dir
	if err != nil {
		t.Fatalf("read custom schema migration: %v", err)
	}

	migrationSQL := strings.ReplaceAll(string(sqlBytes), "authkit", schema)
	if _, err := db.Exec(migrationSQL); err != nil {
		t.Fatalf("apply custom schema migration: %v", err)
	}
}

func assertTablesExist(t *testing.T, db *sql.DB) {
	t.Helper()

	expected := []string{
		"tenants",
		"users",
		"memberships",
		"invitations",
		"api_keys",
		"provider_keys",
		"refresh_tokens",
		"verification_codes",
		"user_status_changes",
	}

	assertTablesExistInSchema(t, db, "authkit", expected...)
}

func assertTablesExistInSchema(t *testing.T, db *sql.DB, schema string, tables ...string) {
	t.Helper()

	if len(tables) == 0 {
		tables = []string{
			"tenants",
			"users",
			"memberships",
			"invitations",
			"api_keys",
			"provider_keys",
			"refresh_tokens",
			"verification_codes",
			"user_status_changes",
		}
	}

	for _, table := range tables {
		var exists bool
		err := db.QueryRow(`
			SELECT EXISTS (
				SELECT 1
				FROM information_schema.tables
				WHERE table_schema = $1
				  AND table_name = $2
			)
		`, schema, table).Scan(&exists)
		if err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if !exists {
			t.Fatalf("expected table %s to exist", table)
		}
	}
}

func createTenantAndUser(t *testing.T, ctx context.Context, repo *repository.Repository, tenantID string) string {
	t.Helper()

	passwordService := service.NewPasswordService(4, nil)
	return createTenantAndUserWithPassword(t, ctx, repo, tenantID, "admin@"+tenantID, "ValidPass1!", passwordService)
}

// createTenantAndUserWithPassword seeds a full login-ready fixture for the decoupled
// model: a tenant, a GLOBAL identity (no tenant/roles on the user), and an ACTIVE
// membership of that identity in the tenant with roles [Admin]. It returns the global
// user id. (Login / token mint require an active membership in the tenant, so every
// caller that authenticates needs all three.)
func createTenantAndUserWithPassword(
	t *testing.T,
	ctx context.Context,
	repo *repository.Repository,
	tenantID string,
	email string,
	password string,
	passwordService *service.PasswordService,
) string {
	t.Helper()

	if err := repo.CreateTenant(ctx, model.CreateTenantRequest{
		TenantID:       tenantID,
		Name:           tenantID,
		AllowedDomains: []string{tenantID},
	}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	return createUserWithPassword(t, ctx, repo, tenantID, email, password, passwordService)
}

// createUserWithPassword creates a GLOBAL identity (globally-unique email, no tenant
// or roles) and grants it an ACTIVE membership of the given tenant with roles [Admin],
// returning the global user id. The tenant must already exist (created by
// createTenantAndUserWithPassword or directly).
func createUserWithPassword(
	t *testing.T,
	ctx context.Context,
	repo *repository.Repository,
	tenantID string,
	email string,
	password string,
	passwordService *service.PasswordService,
) string {
	t.Helper()

	passwordHash, err := passwordService.HashPassword(password)
	if err != nil {
		t.Fatalf("hash test password: %v", err)
	}

	userID, err := repo.Create(ctx, model.CreateUserRequest{
		Email:        email,
		PasswordHash: passwordHash,
		DisplayName:  "Test User",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	if _, err := repo.GetByEmail(ctx, email); err != nil {
		t.Fatalf("get user by email: %v", err)
	}

	grantMembership(t, ctx, repo, userID, tenantID, []string{"Admin"})

	return userID
}

// grantMembership grants (upserts) an ACTIVE membership of userID in tenantID with the
// given roles. Both the user and the tenant must already exist.
func grantMembership(
	t *testing.T,
	ctx context.Context,
	repo *repository.Repository,
	userID string,
	tenantID string,
	roles []string,
) {
	t.Helper()

	if err := repo.AddMembership(ctx, model.AddMembershipRequest{
		UserID:   userID,
		TenantID: tenantID,
		Roles:    roles,
	}); err != nil {
		t.Fatalf("add membership: %v", err)
	}
}

func newIntegrationAuthKit(t *testing.T, db *sql.DB) *authkit.AuthKit {
	t.Helper()

	authKit, err := authkit.New(authkit.Config{
		DBConnection: authkit.DatabaseConnection{
			IdentityRWDB: db,
			IdentityRODB: db,
		},
		JWTConfig: authkit.JWTConfig{
			AccessSecret:           "integration-access-secret-at-least-32-bytes",
			RefreshTokenHMACSecret: "integration-refresh-hmac-secret-at-least-32b",
			AccessExpiry:           5 * time.Minute,
			RefreshExpiry:          time.Hour,
		},
		APIKeyConfig: authkit.APIKeyConfig{
			HMACSecret: "integration-api-hmac-secret-at-least-32-bytes",
		},
		PasswordConfig: authkit.PasswordConfig{
			BcryptCost: 4,
		},
	})
	if err != nil {
		t.Fatalf("new authkit: %v", err)
	}

	return authKit
}

func testRefreshTokenRotation(t *testing.T, ctx context.Context, repo *repository.Repository, userID string) {
	t.Helper()

	oldHash := "old-refresh-hash"
	if _, err := repo.CreateRefreshToken(ctx, repository.CreateRefreshTokenRequest{
		UserID:    userID,
		TokenHash: oldHash,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	user, _, err := repo.RotateRefreshToken(ctx, oldHash, repository.CreateRefreshTokenRequest{
		TokenHash: "new-refresh-hash",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("rotate refresh token: %v", err)
	}
	if user.ID != userID {
		t.Fatalf("rotated token returned user %s, want %s", user.ID, userID)
	}

	// Reusing the already-consumed old token must be detected as reuse/theft.
	_, _, err = repo.RotateRefreshToken(ctx, oldHash, repository.CreateRefreshTokenRequest{
		TokenHash: "should-not-exist",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err == nil {
		t.Fatal("expected reuse of consumed refresh token to fail")
	}
	if !errors.Is(err, model.ErrRefreshTokenReuse) {
		t.Fatalf("expected ErrRefreshTokenReuse, got %v", err)
	}

	// Reuse detection must revoke the whole family, so the active replacement
	// token ("new-refresh-hash") can no longer be rotated either.
	if _, _, err := repo.RotateRefreshToken(ctx, "new-refresh-hash", repository.CreateRefreshTokenRequest{
		TokenHash: "should-also-not-exist",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err == nil {
		t.Fatal("expected family revocation to invalidate the replacement token")
	}
}

func testAPIKeyPersistence(t *testing.T, ctx context.Context, repo *repository.Repository, tenantID string, userID string) {
	t.Helper()

	keyID := uuid.NewString()
	if err := repo.CreateAPIKey(ctx, repository.InsertAPIKeyParams{
		KeyID:     keyID,
		KeyHash:   "api-key-hash",
		TenantID:  tenantID,
		Name:      "Test Key",
		CreatedBy: userID,
	}); err != nil {
		t.Fatalf("create api key: %v", err)
	}

	key, err := repo.GetAPIKeyByHash(ctx, "api-key-hash")
	if err != nil {
		t.Fatalf("get api key by hash: %v", err)
	}
	if key.KeyID != keyID {
		t.Fatalf("api key id = %s, want %s", key.KeyID, keyID)
	}
}

func testOTPPersistence(t *testing.T, ctx context.Context, repo *repository.Repository, tenantID string) {
	t.Helper()

	// Verification codes are keyed by (email, purpose) GLOBALLY now — no tenant.
	email := "verify@" + tenantID

	if _, err := repo.UpsertVerificationCode(ctx, repository.CreateVerificationCodeRequest{
		Email:     email,
		CodeHash:  "123456",
		Purpose:   "signup",
		ExpiresAt: time.Now().Add(time.Hour),
	}, 0); err != nil {
		t.Fatalf("upsert verification code: %v", err)
	}

	// A wrong code counts as a failed attempt but does not consume the code.
	result, err := repo.ConsumeVerificationCode(ctx, email, "000000", "signup", 5)
	if err != nil {
		t.Fatalf("consume wrong code: %v", err)
	}
	if result != repository.OTPConsumeInvalid {
		t.Fatalf("wrong code result = %v, want OTPConsumeInvalid", result)
	}

	// purpose isolation: the correct code under a DIFFERENT purpose must not consume
	// this (email, "signup") code (purpose keys distinct flows so they don't evict
	// each other — the decoupled analogue of the old cross-tenant isolation check).
	result, err = repo.ConsumeVerificationCode(ctx, email, "123456", "reset-password", 5)
	if err != nil {
		t.Fatalf("consume wrong purpose: %v", err)
	}
	if result == repository.OTPConsumeValid {
		t.Fatal("expected a different-purpose OTP consumption to fail")
	}

	// The correct code consumes the OTP (single-use).
	result, err = repo.ConsumeVerificationCode(ctx, email, "123456", "signup", 5)
	if err != nil {
		t.Fatalf("consume code: %v", err)
	}
	if result != repository.OTPConsumeValid {
		t.Fatalf("expected verification code to be consumed, got %v", result)
	}

	// Once consumed it is gone (single-use).
	result, err = repo.ConsumeVerificationCode(ctx, email, "123456", "signup", 5)
	if err != nil {
		t.Fatalf("consume code second time: %v", err)
	}
	if result == repository.OTPConsumeValid {
		t.Fatal("expected consumed verification code to be single-use")
	}
}

func testInvitationPersistence(t *testing.T, ctx context.Context, repo *repository.Repository, tenantID string, userID string) {
	t.Helper()

	if err := repo.CreateInvitation(ctx, repository.InsertInvitationParams{
		Code:      "INVITE12345678901234",
		TenantID:  tenantID,
		CreatedBy: userID,
		Roles:     []string{"Member"},
		Email:     "invitee@acme.test",
		ExpiresAt: time.Now().Add(time.Hour),
		MaxUses:   2,
	}); err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	invitation, err := repo.GetInvitation(ctx, "INVITE12345678901234")
	if err != nil {
		t.Fatalf("get invitation: %v", err)
	}
	if invitation.TenantID != tenantID {
		t.Fatalf("invitation tenant = %s, want %s", invitation.TenantID, tenantID)
	}

	valid, err := repo.IsValid(invitation)
	if err != nil || !valid {
		t.Fatalf("expected invitation to be valid, valid=%v err=%v", valid, err)
	}

	if err := repo.IncrementUseCount(ctx, invitation.Code); err != nil {
		t.Fatalf("increment invitation first use: %v", err)
	}
	if err := repo.IncrementUseCount(ctx, invitation.Code); err != nil {
		t.Fatalf("increment invitation second use: %v", err)
	}
	if err := repo.IncrementUseCount(ctx, invitation.Code); err == nil {
		t.Fatal("expected third invitation use to fail after max uses")
	}

	usedInvitation, err := repo.GetInvitation(ctx, invitation.Code)
	if err != nil {
		t.Fatalf("get used invitation: %v", err)
	}
	if usedInvitation.CurrentUses != usedInvitation.MaxUses {
		t.Fatalf("current uses = %d, want max %d", usedInvitation.CurrentUses, usedInvitation.MaxUses)
	}
}

func testInvitationAccept(t *testing.T, ctx context.Context, repo *repository.Repository, tenantID string, userID string) {
	t.Helper()

	code := "ACCEPTCODE0000000001"
	email := "accept@" + tenantID
	if err := repo.CreateInvitation(ctx, repository.InsertInvitationParams{
		Code:      code,
		TenantID:  tenantID,
		CreatedBy: userID,
		Roles:     []string{"Member"},
		Email:     email,
		ExpiresAt: time.Now().Add(time.Hour),
		MaxUses:   1,
	}); err != nil {
		t.Fatalf("create invitation for accept: %v", err)
	}

	// An email that does not match the invitation must be rejected.
	if _, _, err := repo.AcceptInvitation(ctx, code, "intruder@"+tenantID, "Intruder", "hash"); err == nil {
		t.Fatal("expected accept with mismatched email to fail")
	}

	// Accepting with the correct email creates the GLOBAL identity, grants the invited
	// membership, and consumes the use. created reports a brand-new identity.
	newUserID, created, err := repo.AcceptInvitation(ctx, code, email, "Invited User", "hashed-password")
	if err != nil {
		t.Fatalf("accept invitation: %v", err)
	}
	if !created {
		t.Fatal("expected AcceptInvitation to create a new global identity")
	}

	user, err := repo.GetByID(ctx, newUserID)
	if err != nil {
		t.Fatalf("get accepted user: %v", err)
	}
	if user.Email != email {
		t.Fatalf("accepted user has unexpected email: %+v", user)
	}

	// Roles now live on the membership, not the user: the invited roles are granted
	// as an active membership in the invitation's tenant.
	membership, err := repo.GetMembership(ctx, newUserID, tenantID)
	if err != nil {
		t.Fatalf("get accepted membership: %v", err)
	}
	if !membership.IsActive() || len(membership.Roles) != 1 || membership.Roles[0] != "Member" {
		t.Fatalf("accepted membership has unexpected fields: %+v", membership)
	}

	// The single-use invitation cannot be redeemed again (no over-redemption).
	if _, _, err := repo.AcceptInvitation(ctx, code, email, "Second User", "hashed-password"); err == nil {
		t.Fatal("expected second acceptance of single-use invitation to fail")
	}
}

func testRoleUpdateBumpsTokenVersion(t *testing.T, ctx context.Context, repo *repository.Repository, tenantID string, userID string) {
	t.Helper()

	// Roles are per-membership now: updating them bumps the MEMBERSHIP token_version,
	// invalidating only this workspace's access tokens (the identity token_version is
	// untouched). userID already has an active [Admin] membership from the harness.
	before, err := repo.GetMembership(ctx, userID, tenantID)
	if err != nil {
		t.Fatalf("get membership before role update: %v", err)
	}

	if err := repo.UpdateMembershipRoles(ctx, userID, tenantID, []string{"Viewer"}); err != nil {
		t.Fatalf("update membership roles: %v", err)
	}

	after, err := repo.GetMembership(ctx, userID, tenantID)
	if err != nil {
		t.Fatalf("get membership after role update: %v", err)
	}
	// Role updates must bump the membership token_version so outstanding access tokens
	// for this workspace are rejected.
	if after.TokenVersion != before.TokenVersion+1 {
		t.Fatalf("membership token_version = %d, want %d (role update should bump it)", after.TokenVersion, before.TokenVersion+1)
	}
	if len(after.Roles) != 1 || after.Roles[0] != "Viewer" {
		t.Fatalf("roles = %v, want [Viewer]", after.Roles)
	}
}

func TestValidateRefreshTokenRejectsInactiveAccount(t *testing.T) {
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
	tenantID := "refresh.test"
	userID := createTenantAndUserWithPassword(t, ctx, &repo, tenantID, "refresh@refresh.test", "ValidPass1!", pw)

	authKit := newIntegrationAuthKit(t, db)
	login, err := authKit.AuthService().Login(ctx, model.LoginRequest{
		Email:    "refresh@refresh.test",
		Password: "ValidPass1!",
		TenantID: tenantID,
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	tokenService := authKit.TokenService()
	// While active, the refresh token validates.
	if _, err := tokenService.ValidateRefreshToken(ctx, login.RefreshToken); err != nil {
		t.Fatalf("expected active account refresh token to validate: %v", err)
	}

	// Disable the account (without deleting its refresh tokens) so we isolate the
	// account-status gate in ValidateRefreshToken from token revocation. The
	// repository Disable is identity-level and does NOT revoke refresh tokens (unlike
	// UserService.Disable), so the token survives to reach the status gate.
	if err := repo.Disable(ctx, userID); err != nil {
		t.Fatalf("disable user: %v", err)
	}

	_, err = tokenService.ValidateRefreshToken(ctx, login.RefreshToken)
	if err == nil {
		t.Fatal("expected disabled account's refresh token to be rejected")
	}
	if !errors.Is(err, model.ErrInvalidRefreshToken) {
		t.Fatalf("expected ErrInvalidRefreshToken, got %v", err)
	}
}

func TestDisableRevokesRefreshTokens(t *testing.T) {
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
	tenantID := "disable.test"
	userID := createTenantAndUserWithPassword(t, ctx, &repo, tenantID, "disable@disable.test", "ValidPass1!", pw)

	authKit := newIntegrationAuthKit(t, db)
	if _, err := authKit.AuthService().Login(ctx, model.LoginRequest{
		Email:    "disable@disable.test",
		Password: "ValidPass1!",
		TenantID: tenantID,
	}); err != nil {
		t.Fatalf("login: %v", err)
	}

	// Sanity: login created an active refresh token.
	toks, err := repo.GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("get tokens: %v", err)
	}
	if len(toks) == 0 {
		t.Fatal("expected an active refresh token after login")
	}

	// UserService.Disable (identity-level) must revoke the user's refresh tokens, so a
	// later re-enable cannot resurrect old sessions.
	if err := authKit.UserService().Disable(ctx, userID); err != nil {
		t.Fatalf("disable: %v", err)
	}

	toks, err = repo.GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("get tokens after disable: %v", err)
	}
	if len(toks) != 0 {
		t.Fatalf("expected refresh tokens revoked after Disable, got %d", len(toks))
	}
}

// TestRefreshTokenReuseDetectionViaTokenService is the end-to-end regression test for
// the security fix that motivated the decoupled-identity migration: a consumed refresh
// token, when replayed through the SERVICE-layer rotation (TokenService.RefreshTokenPair),
// must trip reuse/theft detection — the whole token family is revoked, the identity's
// users.token_version is bumped, and the error unwraps to model.ErrRefreshTokenReuse.
//
// The earlier reuse coverage drove the raw repository (RotateRefreshToken); this drives
// the workspace-scoped service path that the product actually calls, which additionally
// runs the active-membership pre-check before rotating. It proves the revoked token is
// NOT short-circuited by that pre-check but falls through to reuse detection.
func TestRefreshTokenReuseDetectionViaTokenService(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")

	repo := repository.New(db, db)
	tenantID := "reuse.test"
	userID := createTenantAndUser(t, ctx, &repo, tenantID) // global identity + active membership

	authKit := newIntegrationAuthKit(t, db)
	tokens := authKit.TokenService()

	user, err := repo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	membership, err := repo.GetMembership(ctx, userID, tenantID)
	if err != nil {
		t.Fatalf("get membership: %v", err)
	}

	tokenVersionBefore := user.TokenVersion

	// Open a session: RT1 (+ a workspace-scoped access token).
	pair, err := tokens.GenerateTokenPair(ctx, user, membership, nil)
	if err != nil {
		t.Fatalf("generate token pair: %v", err)
	}
	rt1 := pair.RefreshToken

	// Rotate once: consumes RT1, returns RT2. RT1 is now a consumed (revoked) token.
	rotated, err := tokens.RefreshTokenPair(ctx, rt1, tenantID, nil)
	if err != nil {
		t.Fatalf("first rotation: %v", err)
	}
	rt2 := rotated.RefreshToken
	if rt2 == "" || rt2 == rt1 {
		t.Fatalf("expected a distinct rotated refresh token, got %q", rt2)
	}

	// Replay RT1 (the consumed token): MUST trip reuse/theft detection.
	_, err = tokens.RefreshTokenPair(ctx, rt1, tenantID, nil)
	if err == nil {
		t.Fatal("expected replay of consumed refresh token to fail")
	}
	if !errors.Is(err, model.ErrRefreshTokenReuse) {
		t.Fatalf("expected error unwrapping to ErrRefreshTokenReuse, got %v", err)
	}

	// The reuse revoked the whole family AND bumped the identity token_version exactly
	// once (assert here, BEFORE replaying RT2, since RT2's replay is itself another
	// consumed-token reuse that would bump the version again).
	after, err := repo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("reload user after reuse: %v", err)
	}
	if after.TokenVersion != tokenVersionBefore+1 {
		t.Fatalf("identity token_version = %d, want %d (reuse must bump it)", after.TokenVersion, tokenVersionBefore+1)
	}
	// Any already-issued access token is now rejected by ValidateJWT.
	if _, err := authKit.AuthService().ValidateJWT(ctx, pair.AccessToken); err == nil {
		t.Fatal("expected the original access token to be revoked after reuse-triggered token_version bump")
	}
	// No active refresh tokens remain for the identity (the whole family is revoked).
	active, err := repo.GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("list refresh tokens after reuse: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected the whole token family revoked, got %d active", len(active))
	}

	// RT2 (the legitimate replacement) no longer works either — its replay is detected
	// as reuse on the already-revoked family.
	if _, err := tokens.RefreshTokenPair(ctx, rt2, tenantID, nil); !errors.Is(err, model.ErrRefreshTokenReuse) {
		t.Fatalf("expected RT2 replay to be rejected as reuse after family revocation, got %v", err)
	}
}

func testSecretPersistence(t *testing.T, ctx context.Context, repo *repository.Repository, tenantID string, userID string) {
	t.Helper()

	secret, err := repo.SaveSecret(ctx, tenantID, "openai", "encrypted-value", "sk-************abcd", userID)
	if err != nil {
		t.Fatalf("save secret: %v", err)
	}
	if secret.Key != "openai" {
		t.Fatalf("secret key = %s, want openai", secret.Key)
	}

	encrypted, err := repo.GetEncryptedSecret(ctx, tenantID, "openai")
	if err != nil {
		t.Fatalf("get encrypted secret: %v", err)
	}
	if encrypted != "encrypted-value" {
		t.Fatalf("encrypted secret = %s, want encrypted-value", encrypted)
	}
}
