// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/modgudinc/authkit-go/repository"
	"github.com/modgudinc/authkit-go/service"
)

func validTestConfig() Config {
	db := &sql.DB{}
	return Config{
		DBConnection: DatabaseConnection{
			IdentityRWDB: db,
			IdentityRODB: db,
		},
		JWTConfig: JWTConfig{
			AccessSecret:           "access-secret-that-is-at-least-32-bytes-long",
			RefreshSecret:          "refresh-secret-that-is-at-least-32-bytes-long",
			RefreshTokenHMACSecret: "refresh-hmac-secret-that-is-at-least-32-bytes",
		},
		APIKeyConfig: APIKeyConfig{
			HMACSecret: "api-hmac-secret-that-is-at-least-32-bytes",
		},
	}
}

func TestNewValidatesRequiredConfig(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "missing rw db",
			mutate: func(config *Config) {
				config.DBConnection.IdentityRWDB = nil
			},
			wantErr: "RW db connection",
		},
		{
			name: "missing ro db",
			mutate: func(config *Config) {
				config.DBConnection.IdentityRODB = nil
			},
			wantErr: "RO db connection",
		},
		{
			name: "missing access secret",
			mutate: func(config *Config) {
				config.JWTConfig.AccessSecret = ""
			},
			wantErr: "access tokens",
		},
		{
			name: "missing refresh secret",
			mutate: func(config *Config) {
				config.JWTConfig.RefreshSecret = ""
			},
			wantErr: "refresh tokens",
		},
		{
			name: "missing refresh hmac secret",
			mutate: func(config *Config) {
				config.JWTConfig.RefreshTokenHMACSecret = ""
			},
			wantErr: "refresh token storage",
		},
		{
			name: "missing api hmac secret",
			mutate: func(config *Config) {
				config.APIKeyConfig.HMACSecret = ""
			},
			wantErr: "API key hashing",
		},
		{
			name: "access secret too short",
			mutate: func(config *Config) {
				config.JWTConfig.AccessSecret = "short"
			},
			wantErr: "at least 32 bytes",
		},
		{
			name: "api hmac secret too short",
			mutate: func(config *Config) {
				config.APIKeyConfig.HMACSecret = "short"
			},
			wantErr: "at least 32 bytes",
		},
		{
			name: "invalid schema",
			mutate: func(config *Config) {
				config.DBConnection.IdentitySchema = "authkit;drop"
			},
			wantErr: "valid PostgreSQL identifier",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validTestConfig()
			test.mutate(&config)

			_, err := New(config)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), test.wantErr)
			}
		})
	}
}

func TestNewAppliesDefaultsAndCustomSchema(t *testing.T) {
	config := validTestConfig()
	config.DBConnection.IdentitySchema = "custom_identity"

	authKit, err := New(config)
	if err != nil {
		t.Fatalf("new authkit: %v", err)
	}

	if authKit.identitySchema != "custom_identity" {
		t.Fatalf("identity schema = %q, want custom_identity", authKit.identitySchema)
	}
	if authKit.accessTokenExpiry != DefaultAccessExpiry {
		t.Fatalf("access expiry = %s, want %s", authKit.accessTokenExpiry, DefaultAccessExpiry)
	}
	if authKit.refreshTokenExpiry != DefaultRefreshExpiry {
		t.Fatalf("refresh expiry = %s, want %s", authKit.refreshTokenExpiry, DefaultRefreshExpiry)
	}
	if authKit.passwordBcryptCost != service.DefaultBcryptCost {
		t.Fatalf("bcrypt cost = %d, want %d", authKit.passwordBcryptCost, service.DefaultBcryptCost)
	}
	if authKit.otpRateLimitDuration != DefaultOTPRateLimitPeriod {
		t.Fatalf("otp rate limit = %s, want %s", authKit.otpRateLimitDuration, DefaultOTPRateLimitPeriod)
	}
}

func TestNewUsesExplicitDurationsAndDefaultSchema(t *testing.T) {
	config := validTestConfig()
	config.JWTConfig.AccessExpiry = 2 * time.Minute
	config.JWTConfig.RefreshExpiry = 3 * time.Hour
	config.OTPConfig.RateLimitDuration = 4 * time.Minute
	config.PasswordConfig.BcryptCost = 5

	authKit, err := New(config)
	if err != nil {
		t.Fatalf("new authkit: %v", err)
	}

	if authKit.identitySchema != repository.DefaultIdentitySchema {
		t.Fatalf("identity schema = %q, want %q", authKit.identitySchema, repository.DefaultIdentitySchema)
	}
	if authKit.accessTokenExpiry != 2*time.Minute {
		t.Fatalf("access expiry = %s", authKit.accessTokenExpiry)
	}
	if authKit.refreshTokenExpiry != 3*time.Hour {
		t.Fatalf("refresh expiry = %s", authKit.refreshTokenExpiry)
	}
	if authKit.otpRateLimitDuration != 4*time.Minute {
		t.Fatalf("otp rate limit = %s", authKit.otpRateLimitDuration)
	}
	if authKit.passwordBcryptCost != 5 {
		t.Fatalf("bcrypt cost = %d", authKit.passwordBcryptCost)
	}
}
