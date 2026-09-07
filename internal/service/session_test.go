// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/model"
)

func TestSessionClaimsCannotDowngrade(t *testing.T) {
	for _, mode := range []model.SessionMode{model.SessionDisabled, model.SessionOptional, model.SessionRequired} {
		s := NewJWTService("test-signing-key", time.Minute, time.Hour, nil, WithSessionMode(mode))
		for _, sid := range []any{"", nil, 42, "invalid-uuid"} {
			raw := jwt.MapClaims{"sid": sid, "exp": time.Now().Add(time.Minute).Unix()}
			token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, raw).SignedString([]byte("test-signing-key"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.ValidateAccessToken(token)
			if !errors.Is(err, model.ErrInvalidToken) {
				t.Fatalf("mode %v sid %v accepted or downgraded: %v", mode, sid, err)
			}
		}
		id := uuid.Must(uuid.NewV7()).String()
		token, err := s.generateAccessToken(&model.User{ID: "u"}, &model.Membership{TenantID: "t"}, id, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		claims, err := s.ValidateAccessToken(token)
		if mode == model.SessionDisabled {
			if !errors.Is(err, model.ErrSessionDisabled) {
				t.Fatal(err)
			}
		} else if err != nil || claims.SessionID != id {
			t.Fatalf("bound token: %v", err)
		}
	}
}

func TestSessionTokenExpiryCapAndSerialization(t *testing.T) {
	j := NewJWTService("test-signing-key", time.Hour, time.Hour, nil, WithSessionMode(model.SessionRequired))
	s := NewTokenService(nil, j, time.Hour, "test-hmac-key", nil, nil, WithTokenSessions(model.SessionConfig{Mode: model.SessionRequired}))
	capTime := time.Now().Add(35 * time.Second)
	session := &model.Session{ID: uuid.Must(uuid.NewV7()).String(), ExpiresAt: capTime, AbsoluteExpiresAt: capTime}
	token, expires, err := s.mintSessionAccess(&model.User{ID: "u"}, &model.Membership{}, session)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := j.ValidateAccessToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ExpiresAt.After(capTime) || expires > 35 {
		t.Fatal("access token exceeds session expiry")
	}
	session.ExpiresAt = time.Now().Add(-time.Second)
	if _, _, err := s.mintSessionAccess(&model.User{}, &model.Membership{}, session); !errors.Is(err, model.ErrSessionRevoked) {
		t.Fatalf("expired session: %v", err)
	}
	encoded, err := json.Marshal(&model.Session{TokenVersion: 7, InstallationID: "mac"})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if _, exists := fields["TokenVersion"]; exists {
		t.Fatal("internal epoch leaked")
	}
}
