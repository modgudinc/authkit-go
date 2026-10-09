//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	authkit "github.com/modgudinc/authkit-go"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/internal/service"
	"github.com/modgudinc/authkit-go/model"
)

func signingKeyKit(t *testing.T, db *sql.DB, secret string, signing *authkit.SigningKey, verification ...authkit.VerificationKey) *authkit.AuthKit {
	t.Helper()
	k, err := authkit.New(authkit.Config{
		DBConnection: authkit.DatabaseConnection{IdentityRWDB: db, IdentityRODB: db},
		JWTConfig: authkit.JWTConfig{
			AccessSecret:           secret,
			SigningKey:             signing,
			VerificationKeys:       verification,
			RefreshTokenHMACSecret: "integration-refresh-hmac-secret-at-least-32b",
			AccessExpiry:           5 * time.Minute, RefreshExpiry: time.Hour,
			Issuer: "authkit-test", Audience: "api",
		},
		APIKeyConfig:   authkit.APIKeyConfig{HMACSecret: "integration-api-hmac-secret-at-least-32-bytes"},
		PasswordConfig: authkit.PasswordConfig{BcryptCost: 4},
	})
	if err != nil {
		t.Fatalf("new authkit: %v", err)
	}
	return k
}

// TestSigningKeySwitch moves a running application from the HS256 secret to an
// Ed25519 signing key with the documented deploys, against a real database: tokens
// and refresh tokens issued before each deploy keep working after it, revocation
// still applies to signed tokens, and the published key set is enough for another
// service to check a token.
func TestSigningKeySwitch(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { applyMigration(t, db, "000001_identity_schema.down.sql"); _ = db.Close() })
	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)

	const secret = "integration-access-secret-at-least-32-bytes"
	const tenantID = "signingkeys.test"
	email := "keys@" + tenantID
	repo := repository.New(db, db)
	userID := createTenantAndUserWithPassword(t, ctx, &repo, tenantID, email, "ValidPass1!", service.NewPasswordService(4, nil))

	_, next, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	before := signingKeyKit(t, db, secret, nil)
	publish := signingKeyKit(t, db, secret, nil, authkit.VerificationKey{ID: "2026-10", Key: next.Public()})
	switched := signingKeyKit(t, db, secret, &authkit.SigningKey{ID: "2026-10", Key: next})
	after := signingKeyKit(t, db, "", &authkit.SigningKey{ID: "2026-10", Key: next})

	login, err := before.AuthService().Login(ctx, model.LoginRequest{Email: email, Password: "ValidPass1!", TenantID: tenantID})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := publish.AuthService().ValidateJWT(ctx, login.AccessToken); err != nil {
		t.Fatalf("HS256 token after publishing the key: %v", err)
	}
	if _, err := switched.AuthService().ValidateJWT(ctx, login.AccessToken); err != nil {
		t.Fatalf("HS256 token after the switch: %v", err)
	}

	// A refresh token from before the switch gets a signed access token after it.
	refreshed, err := switched.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: login.RefreshToken, TenantID: tenantID})
	if err != nil {
		t.Fatalf("refresh after the switch: %v", err)
	}
	header, err := base64.RawURLEncoding.DecodeString(strings.SplitN(refreshed.AccessToken, ".", 2)[0])
	if err != nil || string(header) != `{"alg":"EdDSA","kid":"2026-10","typ":"JWT"}` {
		t.Fatalf("refreshed token is not signed with the key: header %s, %v", header, err)
	}
	for name, kit := range map[string]*authkit.AuthKit{"publish": publish, "switched": switched, "after": after} {
		if _, err := kit.AuthService().ValidateJWT(ctx, refreshed.AccessToken); err != nil {
			t.Fatalf("%s: signed token rejected: %v", name, err)
		}
	}
	if _, err := after.AuthService().ValidateJWT(ctx, login.AccessToken); !errors.Is(err, authkit.ErrInvalidToken) {
		t.Fatalf("HS256 token once the secret is removed: expected ErrInvalidToken, got %v", err)
	}

	// Another service checks the token with nothing but the published key set.
	set := after.JSONWebKeySet()
	if len(set.Keys) != 1 || set.Keys[0].KeyID != "2026-10" || set.Keys[0].Algorithm != "EdDSA" {
		t.Fatalf("key set = %+v", set.Keys)
	}
	x, err := base64.RawURLEncoding.DecodeString(set.Keys[0].X)
	if err != nil {
		t.Fatal(err)
	}
	remoteClaims := &model.JWTClaims{}
	_, err = jwt.ParseWithClaims(refreshed.AccessToken, remoteClaims, func(token *jwt.Token) (any, error) {
		if token.Header["kid"] != set.Keys[0].KeyID {
			return nil, errors.New("unknown key")
		}
		return ed25519.PublicKey(x), nil
	}, jwt.WithValidMethods([]string{set.Keys[0].Algorithm}), jwt.WithIssuer("authkit-test"), jwt.WithAudience("api"))
	if err != nil || remoteClaims.UserID != userID {
		t.Fatalf("token did not check out against the key set: %v", err)
	}

	// Revocation is still the database's call: LogoutAll invalidates signed tokens.
	if err := after.AuthService().LogoutAll(ctx, userID); err != nil {
		t.Fatalf("logout all: %v", err)
	}
	if _, err := after.AuthService().ValidateJWT(ctx, refreshed.AccessToken); !errors.Is(err, authkit.ErrTokenRevoked) {
		t.Fatalf("signed token after LogoutAll: expected ErrTokenRevoked, got %v", err)
	}
}
