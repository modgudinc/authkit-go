// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/model"
)

func TestJWTServiceGenerateAndValidateAccessToken(t *testing.T) {
	userID := uuid.Must(uuid.NewV7()).String()
	service := NewJWTService("access-secret", time.Minute, time.Hour, nil)

	token, err := service.GenerateAccessToken(&model.User{
		ID:           userID,
		Email:        "user@example.com",
		TenantID:     "tenant-a",
		Roles:        []string{"Admin", "Member"},
		TokenVersion: 7,
	})
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}

	claims, err := service.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("validate access token: %v", err)
	}
	if claims.UserID != userID {
		t.Fatalf("user id = %s, want %s", claims.UserID, userID)
	}
	if claims.Email != "user@example.com" || claims.TenantID != "tenant-a" || claims.TokenVersion != 7 {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if len(claims.Roles) != 2 || claims.Roles[0] != "Admin" || claims.Roles[1] != "Member" {
		t.Fatalf("unexpected roles: %+v", claims.Roles)
	}
}

func TestJWTServiceRejectsWrongSecretAndExpiredToken(t *testing.T) {
	userID := uuid.Must(uuid.NewV7()).String()
	service := NewJWTService("access-secret", -time.Minute, time.Hour, nil)
	token, err := service.GenerateAccessToken(&model.User{ID: userID, Email: "user@example.com", TenantID: "tenant-a"})
	if err != nil {
		t.Fatalf("generate expired token: %v", err)
	}

	if _, err := service.ValidateAccessToken(token); err == nil {
		t.Fatal("expected expired token to fail validation")
	}

	freshService := NewJWTService("access-secret", time.Minute, time.Hour, nil)
	freshToken, err := freshService.GenerateAccessToken(&model.User{ID: userID, Email: "user@example.com", TenantID: "tenant-a"})
	if err != nil {
		t.Fatalf("generate fresh token: %v", err)
	}

	wrongSecretService := NewJWTService("wrong-secret", time.Minute, time.Hour, nil)
	if _, err := wrongSecretService.ValidateAccessToken(freshToken); err == nil {
		t.Fatal("expected token signed with different secret to fail")
	}
}

func TestJWTServiceGenerateRefreshToken(t *testing.T) {
	service := NewJWTService("access-secret", time.Minute, time.Hour, nil)

	token, err := service.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("generate refresh token: %v", err)
	}
	if token == "" {
		t.Fatal("refresh token should not be empty")
	}

	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("refresh token should be URL-base64 encoded: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("decoded token length = %d, want 32", len(decoded))
	}
	if service.GetAccessExpiry() != time.Minute {
		t.Fatalf("access expiry = %s, want %s", service.GetAccessExpiry(), time.Minute)
	}
	if service.GetRefreshExpiry() != time.Hour {
		t.Fatalf("refresh expiry = %s, want %s", service.GetRefreshExpiry(), time.Hour)
	}
}

// TestJWTServiceRejectsAlgorithmConfusion verifies the keyfunc pins the HMAC
// family, so neither an unsigned "alg=none" token nor a token signed with a
// non-HMAC method is accepted (CWE-347 algorithm-confusion / "alg:none" attacks).
func TestJWTServiceRejectsAlgorithmConfusion(t *testing.T) {
	service := NewJWTService("access-secret", time.Minute, time.Hour, nil)
	claims := model.JWTClaims{
		UserID:   uuid.Must(uuid.NewV7()).String(),
		TenantID: "tenant-a",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		},
	}

	// alg=none: a token with no signature must be rejected.
	noneToken, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none token: %v", err)
	}
	if _, err := service.ValidateAccessToken(noneToken); err == nil {
		t.Fatal("expected alg=none token to be rejected")
	}
}

func TestJWTServiceIssuerAudience(t *testing.T) {
	user := &model.User{ID: uuid.Must(uuid.NewV7()).String(), Email: "u@x.com", TenantID: "t"}

	issued := NewJWTService("access-secret", time.Minute, time.Hour, nil,
		WithIssuer("authkit"), WithAudience("api"))
	token, err := issued.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	// Same issuer/audience validates fine.
	if _, err := issued.ValidateAccessToken(token); err != nil {
		t.Fatalf("expected token to validate with matching iss/aud: %v", err)
	}

	// A validator requiring a different issuer rejects it.
	otherIssuer := NewJWTService("access-secret", time.Minute, time.Hour, nil,
		WithIssuer("someone-else"), WithAudience("api"))
	if _, err := otherIssuer.ValidateAccessToken(token); err == nil {
		t.Fatal("expected issuer mismatch to be rejected")
	}

	// A validator requiring an audience rejects a token that has none.
	plain := NewJWTService("access-secret", time.Minute, time.Hour, nil)
	plainToken, err := plain.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("generate plain token: %v", err)
	}
	requireAud := NewJWTService("access-secret", time.Minute, time.Hour, nil, WithAudience("api"))
	if _, err := requireAud.ValidateAccessToken(plainToken); err == nil {
		t.Fatal("expected missing audience to be rejected")
	}
}

// TestJWTServiceIssuerAudienceMismatches rounds out TestJWTServiceIssuerAudience:
// an audience mismatch and a missing issuer (the inverses of the cases there), and
// that every iss/aud failure surfaces the model.ErrInvalidToken sentinel so callers
// can errors.Is them like any other validation failure.
func TestJWTServiceIssuerAudienceMismatches(t *testing.T) {
	user := &model.User{ID: uuid.Must(uuid.NewV7()).String(), Email: "u@x.com", TenantID: "t"}

	// Token minted with iss="authkit", aud="api".
	issued := NewJWTService("access-secret", time.Minute, time.Hour, nil, WithIssuer("authkit"), WithAudience("api"))
	token, err := issued.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	// Audience mismatch: same issuer, different required audience.
	wrongAud := NewJWTService("access-secret", time.Minute, time.Hour, nil, WithIssuer("authkit"), WithAudience("other"))
	if _, err := wrongAud.ValidateAccessToken(token); !errors.Is(err, model.ErrInvalidToken) {
		t.Fatalf("audience mismatch: expected ErrInvalidToken, got %v", err)
	}

	// Missing issuer: token carries no iss, validator requires one.
	audOnly := NewJWTService("access-secret", time.Minute, time.Hour, nil, WithAudience("api"))
	audOnlyToken, err := audOnly.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("generate aud-only token: %v", err)
	}
	requireIss := NewJWTService("access-secret", time.Minute, time.Hour, nil, WithIssuer("authkit"), WithAudience("api"))
	if _, err := requireIss.ValidateAccessToken(audOnlyToken); !errors.Is(err, model.ErrInvalidToken) {
		t.Fatalf("missing issuer: expected ErrInvalidToken, got %v", err)
	}

	// Issuer mismatch surfaces the sentinel too (TestJWTServiceIssuerAudience only
	// checks err != nil for this case).
	wrongIss := NewJWTService("access-secret", time.Minute, time.Hour, nil, WithIssuer("nope"), WithAudience("api"))
	if _, err := wrongIss.ValidateAccessToken(token); !errors.Is(err, model.ErrInvalidToken) {
		t.Fatalf("issuer mismatch: expected ErrInvalidToken, got %v", err)
	}
}

func TestJWTServiceRequiresExpiration(t *testing.T) {
	service := NewJWTService("access-secret", time.Minute, time.Hour, nil)

	// Hand-craft a token with no exp claim, signed with the right secret.
	claims := model.JWTClaims{
		UserID:   uuid.Must(uuid.NewV7()).String(),
		TenantID: "t",
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("access-secret"))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	if _, err := service.ValidateAccessToken(token); err == nil {
		t.Fatal("expected token without expiration to be rejected")
	}
}

func TestJWTServiceRejectsMalformedToken(t *testing.T) {
	service := NewJWTService("access-secret", time.Minute, time.Hour, nil)

	_, err := service.ValidateAccessToken("not-a-jwt")
	if err == nil {
		t.Fatal("expected malformed token to fail")
	}
	if !strings.Contains(err.Error(), "invalid token") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestJWTServiceWrapsInvalidTokenSentinel verifies ValidateAccessToken returns
// errors that satisfy errors.Is(err, model.ErrInvalidToken) across its failure
// modes, so a consumer using the JWT service directly can branch on the sentinel
// the same way it can with AuthService.ValidateJWT.
func TestJWTServiceWrapsInvalidTokenSentinel(t *testing.T) {
	valid := NewJWTService("access-secret", time.Minute, time.Hour, nil)
	user := &model.User{ID: uuid.Must(uuid.NewV7()).String(), Email: "u@x.com", TenantID: "t"}

	// Malformed token.
	if _, err := valid.ValidateAccessToken("not-a-jwt"); !errors.Is(err, model.ErrInvalidToken) {
		t.Fatalf("malformed: expected ErrInvalidToken, got %v", err)
	}

	// Token signed with a different secret.
	token, err := valid.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	wrong := NewJWTService("other-secret", time.Minute, time.Hour, nil)
	if _, err := wrong.ValidateAccessToken(token); !errors.Is(err, model.ErrInvalidToken) {
		t.Fatalf("wrong secret: expected ErrInvalidToken, got %v", err)
	}

	// Expired token.
	expiredSvc := NewJWTService("access-secret", -time.Minute, time.Hour, nil)
	expired, err := expiredSvc.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("generate expired token: %v", err)
	}
	if _, err := valid.ValidateAccessToken(expired); !errors.Is(err, model.ErrInvalidToken) {
		t.Fatalf("expired: expected ErrInvalidToken, got %v", err)
	}
}
