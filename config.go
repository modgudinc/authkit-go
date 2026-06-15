// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"database/sql"
	"time"

	"github.com/modgudinc/authkit-go/logger"
)

// Config is the configuration passed to New to construct an AuthKit. The
// DBConnection and the JWT/API-key secrets are required; the remaining fields
// have sensible defaults. See each sub-struct for details.
type Config struct {
	DBConnection   DatabaseConnection
	JWTConfig      JWTConfig
	APIKeyConfig   APIKeyConfig
	PasswordConfig PasswordConfig
	OTPConfig      OTPConfig
	SecretConfig   SecretConfig  // Optional: Configuration for SecretService
	Logger         logger.Logger // Optional: Logger implementation for structured logging
}

// DatabaseConnection holds the PostgreSQL handles and schema for the identity
// store. The read-write and read-only handles may be the same *sql.DB.
type DatabaseConnection struct {
	// Identity schema connections (authkit)
	IdentityRWDB   *sql.DB // For user/session management and audit logging (read-write)
	IdentityRODB   *sql.DB // For auth lookups (SELECT only)
	IdentitySchema string  // Optional PostgreSQL schema name (defaults to authkit)
}

// JWTConfig configures access-token signing and refresh-token hashing.
// AccessSecret and RefreshTokenHMACSecret are required and must each be at least
// MinSecretLength bytes of high-entropy random data. Expiries default to
// DefaultAccessExpiry / DefaultRefreshExpiry when zero.
//
// Note: refresh tokens are opaque random strings, not JWTs — they are not signed,
// only HMAC-hashed (with RefreshTokenHMACSecret) for storage. There is therefore
// no separate refresh-token signing secret.
type JWTConfig struct {
	AccessSecret           string
	RefreshTokenHMACSecret string // Secret for HMAC-SHA256 hashing of refresh tokens in storage
	AccessExpiry           time.Duration
	RefreshExpiry          time.Duration
	Issuer                 string // Optional: if set, stamped as the "iss" claim and required on validation
	Audience               string // Optional: if set, stamped as the "aud" claim and required on validation
}

// APIKeyConfig configures API key hashing. HMACSecret is required and must be at
// least MinSecretLength bytes of high-entropy random data.
type APIKeyConfig struct {
	HMACSecret string // Secret key for HMAC-SHA256 hashing of API keys
}

// PasswordConfig configures password hashing.
type PasswordConfig struct {
	BcryptCost int // Cost factor for bcrypt hashing (default: 12, range: 4-31)
}

// OTPConfig configures OTP generation behavior.
type OTPConfig struct {
	RateLimitDuration time.Duration // Minimum time between OTP generation attempts (default: 1 minute)
}

// SecretConfig configures the optional SecretService. EncryptionKey is only
// required if SecretService is used.
type SecretConfig struct {
	EncryptionKey string // Base64-encoded 32-byte AES-256 key for encrypting secrets
}
