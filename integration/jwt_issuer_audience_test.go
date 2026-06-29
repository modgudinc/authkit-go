//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	authkit "github.com/modgudinc/authkit-go"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/internal/service"
	"github.com/modgudinc/authkit-go/model"
)

// TestAuthServiceJWTIssuerAudience verifies the public iss/aud config plumbing:
// JWTConfig.Issuer/Audience -> authkit.New -> JWTService -> AuthService.ValidateJWT.
// The JWT-layer iss/aud logic is unit-tested in jwt_test.go; this guards the wiring
// in main.go (e.g. a regression that dropped WithIssuer/WithAudience would make
// ValidateJWT silently stop enforcing them, which no unit test would catch).
func TestAuthServiceJWTIssuerAudience(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	defer func() {
		applyMigration(t, db, "000001_identity_schema.down.sql")
		_ = db.Close()
	}()

	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")

	const (
		accessSecret = "integration-access-secret-at-least-32-bytes"
		issuer       = "authkit-issuer"
		audience     = "modgud-api"
	)

	repo := repository.New(db, db)
	authKit, err := authkit.New(authkit.Config{
		DBConnection: authkit.DatabaseConnection{IdentityRWDB: db, IdentityRODB: db},
		JWTConfig: authkit.JWTConfig{
			AccessSecret:           accessSecret,
			RefreshTokenHMACSecret: "integration-refresh-hmac-secret-at-least-32b",
			AccessExpiry:           5 * time.Minute,
			RefreshExpiry:          time.Hour,
			Issuer:                 issuer,   // <- the wiring under test
			Audience:               audience, // <-
		},
		APIKeyConfig:   authkit.APIKeyConfig{HMACSecret: "integration-api-hmac-secret-at-least-32-bytes"},
		PasswordConfig: authkit.PasswordConfig{BcryptCost: 4},
	})
	if err != nil {
		t.Fatalf("new authkit: %v", err)
	}
	auth := authKit.AuthService()

	pw := service.NewPasswordService(4, nil)
	tenantID := "jwtissaud.test"
	email := "iss@" + tenantID
	createTenantAndUserWithPassword(t, ctx, &repo, tenantID, email, "ValidPass1!", pw)

	// Happy path: Login mints a token stamped with the configured iss/aud, and
	// ValidateJWT (which requires them) accepts it — proving the config takes effect.
	login, err := auth.Login(ctx, model.LoginRequest{Email: email, Password: "ValidPass1!", TenantID: tenantID})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := auth.ValidateJWT(ctx, login.AccessToken); err != nil {
		t.Fatalf("expected token with configured iss/aud to validate: %v", err)
	}

	user, err := repo.GetByEmail(ctx, email, tenantID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	// A token signed with the SAME secret but a WRONG issuer/audience is rejected.
	// The iss/aud check runs before any DB lookup, so the user being perfectly valid
	// (correct token_version, enabled, unlocked) does not let it through.
	wrong := service.NewJWTService(accessSecret, 5*time.Minute, time.Hour, nil,
		service.WithIssuer("evil-issuer"), service.WithAudience("evil-aud"))
	wrongToken, err := wrong.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("generate wrong iss/aud token: %v", err)
	}
	if _, err := auth.ValidateJWT(ctx, wrongToken); !errors.Is(err, model.ErrInvalidToken) {
		t.Fatalf("expected wrong iss/aud token rejected with ErrInvalidToken, got %v", err)
	}

	// A token carrying NO iss/aud is likewise rejected by the configured validator.
	plain := service.NewJWTService(accessSecret, 5*time.Minute, time.Hour, nil)
	plainToken, err := plain.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("generate plain token: %v", err)
	}
	if _, err := auth.ValidateJWT(ctx, plainToken); !errors.Is(err, model.ErrInvalidToken) {
		t.Fatalf("expected token missing iss/aud rejected with ErrInvalidToken, got %v", err)
	}
}
