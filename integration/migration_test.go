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
	defer db.Close()

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
	testRoleUpdateBumpsTokenVersion(t, ctx, &repo, tenantID)
	testSecretPersistence(t, ctx, &repo, tenantID, userID)
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

	refreshed, err := authService.RefreshToken(ctx, model.RefreshRequest{RefreshToken: login.RefreshToken})
	if err != nil {
		t.Fatalf("refresh token: %v", err)
	}
	if refreshed.UserID != loginUserID || refreshed.RefreshToken == "" || refreshed.RefreshToken == login.RefreshToken {
		t.Fatalf("unexpected refresh response: %+v", refreshed)
	}

	if _, err := authService.RefreshToken(ctx, model.RefreshRequest{RefreshToken: login.RefreshToken}); err == nil {
		t.Fatal("expected old refresh token to fail after rotation")
	}

	if err := authService.Logout(ctx, refreshed.RefreshToken); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := authService.RefreshToken(ctx, model.RefreshRequest{RefreshToken: refreshed.RefreshToken}); err == nil {
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
	if err := authService.LogoutAll(ctx, loginUserID, tenantID); err != nil {
		t.Fatalf("logout all: %v", err)
	}
	if _, err := authService.ValidateJWT(ctx, secondLogin.AccessToken); err == nil {
		t.Fatal("expected access token to fail after logout all increments token version")
	}
	if _, err := authService.RefreshToken(ctx, model.RefreshRequest{RefreshToken: secondLogin.RefreshToken}); err == nil {
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

	lockedUser, err := repo.GetByID(ctx, lockoutUserID, tenantID)
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

func TestCustomSchemaAndTenantScopedEmails(t *testing.T) {
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

	userA := createTenantAndUserWithPassword(t, ctx, &repo, "tenant-a.test", "shared@example.test", "ValidPass1!", passwordService)
	userB := createTenantAndUserWithPassword(t, ctx, &repo, "tenant-b.test", "shared@example.test", "ValidPass1!", passwordService)

	if userA == userB {
		t.Fatal("expected duplicate email across tenants to create distinct users")
	}

	gotA, err := repo.GetByEmail(ctx, "shared@example.test", "tenant-a.test")
	if err != nil {
		t.Fatalf("get tenant-a user by email: %v", err)
	}
	gotB, err := repo.GetByEmail(ctx, "shared@example.test", "tenant-b.test")
	if err != nil {
		t.Fatalf("get tenant-b user by email: %v", err)
	}
	if gotA.ID != userA || gotB.ID != userB {
		t.Fatalf("tenant-scoped lookup returned wrong users: %s/%s", gotA.ID, gotB.ID)
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
	sqlBytes, err := os.ReadFile(path)
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
	sqlBytes, err := os.ReadFile(path)
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

func createTenantAndUser(t *testing.T, ctx context.Context, repo *repository.Repository, tenantID string) uuid.UUID {
	t.Helper()

	passwordService := service.NewPasswordService(4, nil)
	return createTenantAndUserWithPassword(t, ctx, repo, tenantID, "admin@"+tenantID, "ValidPass1!", passwordService)
}

func createTenantAndUserWithPassword(
	t *testing.T,
	ctx context.Context,
	repo *repository.Repository,
	tenantID string,
	email string,
	password string,
	passwordService *service.PasswordService,
) uuid.UUID {
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

func createUserWithPassword(
	t *testing.T,
	ctx context.Context,
	repo *repository.Repository,
	tenantID string,
	email string,
	password string,
	passwordService *service.PasswordService,
) uuid.UUID {
	t.Helper()

	passwordHash, err := passwordService.HashPassword(password)
	if err != nil {
		t.Fatalf("hash test password: %v", err)
	}

	userID, err := repo.Create(ctx, model.CreateUserRequest{
		Email:        email,
		PasswordHash: passwordHash,
		TenantID:     tenantID,
		DisplayName:  "Test User",
		Roles:        []string{"Admin"},
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	if _, err := repo.GetByEmail(ctx, email, tenantID); err != nil {
		t.Fatalf("get user by email: %v", err)
	}

	return userID
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

func testRefreshTokenRotation(t *testing.T, ctx context.Context, repo *repository.Repository, userID uuid.UUID) {
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

func testAPIKeyPersistence(t *testing.T, ctx context.Context, repo *repository.Repository, tenantID string, userID uuid.UUID) {
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

	email := "verify@" + tenantID

	if _, err := repo.UpsertVerificationCode(ctx, repository.CreateVerificationCodeRequest{
		TenantID:  tenantID,
		Email:     email,
		Code:      "123456",
		Purpose:   "signup",
		ExpiresAt: time.Now().Add(time.Hour),
	}, 0); err != nil {
		t.Fatalf("upsert verification code: %v", err)
	}

	// A wrong code counts as a failed attempt but does not consume the code.
	result, err := repo.ConsumeVerificationCode(ctx, tenantID, email, "000000", "signup", 5)
	if err != nil {
		t.Fatalf("consume wrong code: %v", err)
	}
	if result != repository.OTPConsumeInvalid {
		t.Fatalf("wrong code result = %v, want OTPConsumeInvalid", result)
	}

	// A cross-tenant attempt must not consume this tenant's code.
	result, err = repo.ConsumeVerificationCode(ctx, "other-tenant.test", email, "123456", "signup", 5)
	if err != nil {
		t.Fatalf("consume cross-tenant: %v", err)
	}
	if result == repository.OTPConsumeValid {
		t.Fatal("expected cross-tenant OTP consumption to fail")
	}

	// The correct code consumes the OTP (single-use).
	result, err = repo.ConsumeVerificationCode(ctx, tenantID, email, "123456", "signup", 5)
	if err != nil {
		t.Fatalf("consume code: %v", err)
	}
	if result != repository.OTPConsumeValid {
		t.Fatalf("expected verification code to be consumed, got %v", result)
	}

	// Once consumed it is gone (single-use).
	result, err = repo.ConsumeVerificationCode(ctx, tenantID, email, "123456", "signup", 5)
	if err != nil {
		t.Fatalf("consume code second time: %v", err)
	}
	if result == repository.OTPConsumeValid {
		t.Fatal("expected consumed verification code to be single-use")
	}
}

func testInvitationPersistence(t *testing.T, ctx context.Context, repo *repository.Repository, tenantID string, userID uuid.UUID) {
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

func testInvitationAccept(t *testing.T, ctx context.Context, repo *repository.Repository, tenantID string, userID uuid.UUID) {
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
	if _, err := repo.AcceptInvitation(ctx, code, "intruder@"+tenantID, "Intruder", "hash"); err == nil {
		t.Fatal("expected accept with mismatched email to fail")
	}

	// Accepting with the correct email creates the user and consumes the use.
	newUserID, err := repo.AcceptInvitation(ctx, code, email, "Invited User", "hashed-password")
	if err != nil {
		t.Fatalf("accept invitation: %v", err)
	}

	created, err := repo.GetByID(ctx, newUserID, tenantID)
	if err != nil {
		t.Fatalf("get accepted user: %v", err)
	}
	if created.Email != email || len(created.Roles) != 1 || created.Roles[0] != "Member" {
		t.Fatalf("accepted user has unexpected fields: %+v", created)
	}

	// The single-use invitation cannot be redeemed again (no over-redemption).
	if _, err := repo.AcceptInvitation(ctx, code, email, "Second User", "hashed-password"); err == nil {
		t.Fatal("expected second acceptance of single-use invitation to fail")
	}
}

func testRoleUpdateBumpsTokenVersion(t *testing.T, ctx context.Context, repo *repository.Repository, tenantID string) {
	t.Helper()

	pw := service.NewPasswordService(4, nil)
	uid := createUserWithPassword(t, ctx, repo, tenantID, "rolecheck@"+tenantID, "ValidPass1!", pw)

	before, err := repo.GetByID(ctx, uid, tenantID)
	if err != nil {
		t.Fatalf("get user before role update: %v", err)
	}

	if err := repo.UpdateRolesByTenant(ctx, uid, tenantID, []string{"Viewer"}); err != nil {
		t.Fatalf("update roles: %v", err)
	}

	after, err := repo.GetByID(ctx, uid, tenantID)
	if err != nil {
		t.Fatalf("get user after role update: %v", err)
	}
	// Role updates must bump token_version so outstanding access tokens are rejected.
	if after.TokenVersion != before.TokenVersion+1 {
		t.Fatalf("token_version = %d, want %d (role update should bump it)", after.TokenVersion, before.TokenVersion+1)
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
	// account-status gate in ValidateRefreshToken from token revocation.
	if err := repo.DisableByTenant(ctx, userID, tenantID); err != nil {
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

func TestDisableByTenantRevokesRefreshTokens(t *testing.T) {
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

	// Disable must revoke the user's refresh tokens (parity with Disable),
	// so a later re-enable cannot resurrect old sessions.
	if err := authKit.UserService().Disable(ctx, userID, tenantID); err != nil {
		t.Fatalf("disable by tenant: %v", err)
	}

	toks, err = repo.GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("get tokens after disable: %v", err)
	}
	if len(toks) != 0 {
		t.Fatalf("expected refresh tokens revoked after Disable, got %d", len(toks))
	}
}

func testSecretPersistence(t *testing.T, ctx context.Context, repo *repository.Repository, tenantID string, userID uuid.UUID) {
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
