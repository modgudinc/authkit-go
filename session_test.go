// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/modgudinc/authkit-go/model"
)

func TestSessionConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name    string
		config  SessionConfig
		invalid bool
	}{
		{"default", SessionConfig{}, false},
		{"optional", SessionConfig{Mode: SessionOptional, Namespace: "hugin"}, false},
		{"required", SessionConfig{Mode: SessionRequired, Namespace: "hugin", AbsoluteLifetime: time.Hour}, false},
		{"bad mode", SessionConfig{Mode: 99}, true},
		{"empty namespace", SessionConfig{Mode: SessionRequired}, true},
		{"padded namespace", SessionConfig{Mode: SessionOptional, Namespace: " hugin"}, true},
		{"long namespace", SessionConfig{Mode: SessionRequired, Namespace: strings.Repeat("x", 256)}, true},
		{"negative lifetime", SessionConfig{AbsoluteLifetime: -time.Second}, true},
		{"tiny lifetime", SessionConfig{Mode: SessionOptional, Namespace: "hugin", AbsoluteLifetime: time.Nanosecond}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := validTestConfig()
			config.SessionConfig = tc.config
			k, err := New(config)
			if (err != nil) != tc.invalid {
				t.Fatalf("New error = %v", err)
			}
			if err == nil && tc.config.Mode != SessionDisabled && tc.config.AbsoluteLifetime == 0 && k.sessionConfig.AbsoluteLifetime != 30*24*time.Hour {
				t.Fatal("unexpected default lifetime")
			}
		})
	}
}

// The intentionally unusable sql.DB in validTestConfig proves disabled and
// required-mode input gates do not attempt a session query or a token write.
func TestSessionDisabledAndRequiredGatesWithoutDatabase(t *testing.T) {
	ctx := context.Background()
	k, err := New(validTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	_, err = k.SessionService().Get(ctx, "user", "session")
	assertSessionError(t, err, ErrSessionDisabled)
	_, err = k.SessionService().List(ctx, "user", 10, 0)
	assertSessionError(t, err, ErrSessionDisabled)
	assertSessionError(t, k.SessionService().Revoke(ctx, "user", "session"), ErrSessionDisabled)
	assertSessionError(t, k.SessionService().RevokeInstallation(ctx, "user", "device"), ErrSessionDisabled)
	_, err = k.SessionService().CleanupExpired(ctx)
	assertSessionError(t, err, ErrSessionDisabled)
	_, err = k.InstallationAuthService().LoginWithInstallation(ctx, model.InstallationLoginRequest{})
	assertSessionError(t, err, ErrSessionDisabled)
	_, err = k.TokenService().ValidateRefreshToken(ctx, "s1.opaque")
	assertSessionError(t, err, ErrSessionDisabled)
	config := validTestConfig()
	config.SessionConfig = SessionConfig{Mode: SessionRequired, Namespace: "app"}
	k, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = k.AuthService().Login(ctx, model.LoginRequest{})
	assertSessionError(t, err, ErrSessionRequired)
	_, err = k.AuthService().LoginByEmail(ctx, model.LoginByEmailRequest{})
	assertSessionError(t, err, ErrSessionRequired)
	_, err = k.TokenService().GenerateTokenPair(ctx, nil, nil, nil)
	assertSessionError(t, err, ErrSessionRequired)
	_, err = k.JWTService().GenerateAccessToken(nil, nil)
	assertSessionError(t, err, ErrSessionRequired)
	_, err = k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: "legacy"})
	assertSessionError(t, err, ErrSessionRequired)
	_, err = k.InstallationAuthService().LoginWithInstallation(ctx, model.InstallationLoginRequest{})
	assertSessionError(t, err, ErrInvalidInput)
	_, err = k.SessionService().List(ctx, "user", 201, 0)
	assertSessionError(t, err, ErrInvalidInput)
	assertSessionError(t, k.SessionService().RevokeInstallation(ctx, "user", ""), ErrInvalidInput)
}

func assertSessionError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}
