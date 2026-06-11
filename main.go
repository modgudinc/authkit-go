// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package authkit is a multi-tenant identity and authentication library for Go,
// backed by PostgreSQL. It provides users and tenants, JWT access tokens with
// rotating refresh tokens, API keys, OTP verification, invitations, and
// encrypted provider secrets.
//
// Construct an AuthKit with New and a Config, then obtain the individual
// services (AuthService, UserService, etc.) from it:
//
//	kit, err := authkit.New(authkit.Config{ /* ... */ })
//	if err != nil {
//	    return err
//	}
//	auth := kit.AuthService()
//
// Authentication outcomes are returned as sentinel errors (authkit.Err*), so
// callers should branch with errors.Is rather than matching error strings.
package authkit

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/repository"
	"github.com/modgudinc/authkit-go/service"
)

const (
	DefaultAccessExpiry       = time.Minute * 15
	DefaultRefreshExpiry      = time.Hour * 168
	DefaultOTPRateLimitPeriod = time.Minute * 1

	// MinSecretLength is the minimum length (in bytes) required for the JWT
	// signing secrets and HMAC secrets. HS256/HMAC-SHA256 security depends on a
	// key with at least the hash output size of entropy (256 bits = 32 bytes,
	// per RFC 7518). Shorter secrets are brute-forceable offline against any
	// captured token, so they are rejected at construction time.
	MinSecretLength = 32
)

// AuthKit is the library entrypoint created by New. It is safe for concurrent
// use and holds the configured connections, secrets, and options. Obtain the
// individual services through its accessor methods (AuthService, UserService,
// TokenService, etc.).
type AuthKit struct {
	rwConnection *sql.DB
	roConnection *sql.DB

	accessTokenSecret      string
	refreshTokenSecret     string
	refreshTokenHMACSecret string // Secret for HMAC-SHA256 hashing of refresh tokens in storage
	jwtIssuer              string // Optional "iss" claim
	jwtAudience            string // Optional "aud" claim

	accessTokenExpiry  time.Duration
	refreshTokenExpiry time.Duration

	apiKeyHMACSecret     string
	passwordBcryptCost   int
	otpRateLimitDuration time.Duration
	secretEncryptionKey  []byte // 32-byte AES-256 key for encrypting secrets
	identitySchema       string
	logger               logger.Logger
}

// New validates the Config and returns a configured AuthKit. It fails fast if a
// required connection or secret is missing, a secret is shorter than
// MinSecretLength, the identity schema is not a valid identifier, or the secret
// encryption key (when provided) is not a base64-encoded 32-byte key.
func New(config Config) (AuthKit, error) {
	if config.DBConnection.IdentityRWDB == nil {
		return AuthKit{}, errors.New("RW db connection for identity schema is required")
	}

	if config.DBConnection.IdentityRODB == nil {
		return AuthKit{}, errors.New("RO db connection for identity schema is required")
	}

	if config.JWTConfig.AccessSecret == "" {
		return AuthKit{}, errors.New("signing secret for access tokens is required")
	}

	if config.JWTConfig.RefreshSecret == "" {
		return AuthKit{}, errors.New("signing secret for refresh tokens is required")
	}

	if config.JWTConfig.RefreshTokenHMACSecret == "" {
		return AuthKit{}, errors.New("HMAC secret for refresh token storage hashing is required")
	}

	if config.APIKeyConfig.HMACSecret == "" {
		return AuthKit{}, errors.New("HMAC secret for API key hashing is required")
	}

	// Reject weak/short secrets. A short secret silently passes the non-empty
	// checks above but is offline-brute-forceable, allowing token forgery.
	for _, s := range []struct {
		name  string
		value string
	}{
		{"access token signing secret", config.JWTConfig.AccessSecret},
		{"refresh token signing secret", config.JWTConfig.RefreshSecret},
		{"refresh token HMAC secret", config.JWTConfig.RefreshTokenHMACSecret},
		{"API key HMAC secret", config.APIKeyConfig.HMACSecret},
	} {
		if len(s.value) < MinSecretLength {
			return AuthKit{}, fmt.Errorf("%s must be at least %d bytes of high-entropy random data", s.name, MinSecretLength)
		}
	}

	identitySchema := config.DBConnection.IdentitySchema
	if identitySchema == "" {
		identitySchema = repository.DefaultIdentitySchema
	}
	if !repository.IsIdentifier(identitySchema) {
		return AuthKit{}, errors.New("identity schema must be a valid PostgreSQL identifier")
	}

	accessTokenExpiry := DefaultAccessExpiry
	if config.JWTConfig.AccessExpiry > 0 {
		accessTokenExpiry = config.JWTConfig.AccessExpiry
	}

	refreshTokenExpiry := DefaultRefreshExpiry
	if config.JWTConfig.RefreshExpiry > 0 {
		refreshTokenExpiry = config.JWTConfig.RefreshExpiry
	}

	// Set bcrypt cost (default to service.DefaultBcryptCost if not specified or invalid)
	passwordBcryptCost := config.PasswordConfig.BcryptCost
	if passwordBcryptCost <= 0 {
		passwordBcryptCost = service.DefaultBcryptCost
	}

	// Set OTP rate limit duration (default to DefaultOTPRateLimitPeriod if not specified)
	otpRateLimitDuration := DefaultOTPRateLimitPeriod
	if config.OTPConfig.RateLimitDuration > 0 {
		otpRateLimitDuration = config.OTPConfig.RateLimitDuration
	}

	// Validate and decode secret encryption key (optional - only required if using SecretService)
	var secretEncryptionKey []byte
	if config.SecretConfig.EncryptionKey != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(config.SecretConfig.EncryptionKey)
		if err != nil {
			return AuthKit{}, errors.New("invalid secret encryption key: must be base64 encoded")
		}
		if len(keyBytes) != 32 {
			return AuthKit{}, errors.New("secret encryption key must be 32 bytes (256 bits)")
		}
		secretEncryptionKey = keyBytes
	}

	return AuthKit{
		rwConnection: config.DBConnection.IdentityRWDB,
		roConnection: config.DBConnection.IdentityRODB,

		accessTokenSecret:      config.JWTConfig.AccessSecret,
		refreshTokenSecret:     config.JWTConfig.RefreshSecret,
		refreshTokenHMACSecret: config.JWTConfig.RefreshTokenHMACSecret,
		jwtIssuer:              config.JWTConfig.Issuer,
		jwtAudience:            config.JWTConfig.Audience,

		accessTokenExpiry:  accessTokenExpiry,
		refreshTokenExpiry: refreshTokenExpiry,

		apiKeyHMACSecret:     config.APIKeyConfig.HMACSecret,
		passwordBcryptCost:   passwordBcryptCost,
		otpRateLimitDuration: otpRateLimitDuration,
		secretEncryptionKey:  secretEncryptionKey,
		identitySchema:       identitySchema,
		logger:               config.Logger,
	}, nil
}

// APIKeyService returns a configured API key service instance
// for managing tenant-scoped API keys (creation, validation, revocation)
func (c *AuthKit) APIKeyService() *service.APIKeyService {
	repo := c.repository()
	return service.NewAPIKeyService(&repo, c.apiKeyHMACSecret, c.logger)
}

// PasswordService returns a configured password service instance
// for password hashing and verification using bcrypt
func (c *AuthKit) PasswordService() *service.PasswordService {
	return service.NewPasswordService(c.passwordBcryptCost, c.logger)
}

// JWTService returns a configured JWT service instance
// for generating and validating JWT access tokens and refresh tokens
func (c *AuthKit) JWTService() *service.JWTService {
	return service.NewJWTService(
		c.accessTokenSecret,
		c.refreshTokenSecret,
		c.accessTokenExpiry,
		c.refreshTokenExpiry,
		c.logger,
		service.WithIssuer(c.jwtIssuer),
		service.WithAudience(c.jwtAudience),
	)
}

// TokenService returns a configured token service instance
// for combined JWT and refresh token management with token rotation
func (c *AuthKit) TokenService() *service.TokenService {
	repo := c.repository()
	jwtService := c.JWTService()
	return service.NewTokenService(&repo, jwtService, c.refreshTokenExpiry, c.refreshTokenHMACSecret, c.logger)
}

// AuthService returns a configured authentication service instance
// for complete authentication flows (login, logout, token refresh, JWT validation)
func (c *AuthKit) AuthService() *service.AuthService {
	repo := c.repository()
	passwordService := c.PasswordService()
	tokenService := c.TokenService()
	jwtService := c.JWTService()
	return service.NewAuthService(&repo, passwordService, tokenService, jwtService, c.logger)
}

// OTPService returns a configured OTP service instance
// for OTP generation, validation, and lifecycle management with rate limiting
func (c *AuthKit) OTPService() *service.OTPService {
	repo := c.repository()
	return service.NewOTPService(&repo, c.otpRateLimitDuration, c.logger)
}

// TenantService returns a configured tenant service instance
// for tenant management, settings, and domain validation
func (c *AuthKit) TenantService() *service.TenantService {
	repo := c.repository()
	return service.NewTenantService(&repo, c.logger)
}

// InvitationService returns a configured invitation service instance
// for invitation management, validation, and lifecycle operations
func (c *AuthKit) InvitationService() *service.InvitationService {
	repo := c.repository()
	return service.NewInvitationService(&repo, c.logger)
}

// SecretService returns a configured secret service instance
// for managing encrypted secrets (provider API keys, etc.)
//
// IMPORTANT: SecretConfig.EncryptionKey must be configured for this service to work.
// The encryption key must be a base64-encoded 32-byte (256-bit) key.
func (c *AuthKit) SecretService() *service.SecretService {
	repo := c.repository()
	return service.NewSecretService(&repo, c.secretEncryptionKey, c.logger)
}

// UserService returns a configured user service instance
// for user management, queries, and account status operations
func (c *AuthKit) UserService() *service.UserService {
	repo := c.repository()
	return service.NewUserService(&repo, c.logger)
}

func (c *AuthKit) repository() repository.Repository {
	return repository.NewWithSchema(c.rwConnection, c.roConnection, c.identitySchema)
}
