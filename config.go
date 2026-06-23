// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"database/sql"
	"time"

	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/metrics"
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
	SecretConfig   SecretConfig // Optional: Configuration for SecretService
	// Logger is optional and defaults to a no-op that discards everything. NOTE
	// that several security signals are logger-only: OTP lockouts, refresh-token
	// reuse, and sub-threshold failed logins are emitted only via the logger and
	// are LOST if none is injected. (Account lock/disable/enable transitions, by
	// contrast, are persisted to the user_status_changes audit table regardless.)
	// Inject a Logger in production, and/or supply Metrics below to capture the
	// theft/abuse counters that are not covered by the status-change audit.
	Logger logger.Logger
	// Metrics is an optional counter sink for auth security/operational events
	// (login success/failure, account lockout, OTP failure/lockout, refresh-token
	// reuse). Defaults to a no-op. See the metrics package for the canonical
	// counter names. Unlike the logger, these survive independently of log level,
	// so they are the recommended basis for alerting.
	Metrics metrics.Metrics

	// VerifyConnectivity, when true, makes New ping both database handles (with a
	// short internal timeout) and fail if either is unreachable, instead of
	// deferring the first connection error to the first query. Off by default so
	// construction stays cheap and offline-testable; turn it on for fail-fast
	// startup, or call AuthKit.Ping from a readiness probe.
	VerifyConnectivity bool

	// RateLimiter is an optional pluggable throttle consulted by AuthService.Login,
	// RefreshToken, and OTPService.Generate before they do work. It is the
	// recommended place to enforce the IP/global rate limiting the library does not
	// do itself (the per-account lockout is not enough — see SECURITY.md). Defaults
	// to no limiting. See the RateLimiter interface for the key convention.
	RateLimiter RateLimiter
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
//
// HMACSecret is required when OTPService is used: OTP codes are stored as a keyed
// HMAC-SHA256 (not in plaintext), so the secret must be at least MinSecretLength
// bytes of high-entropy random data. It is validated for length at construction
// when non-empty; OTPService.Generate/Validate return ErrOTPSecretMissing if it is
// absent. Use a value distinct from the JWT/API-key/encryption secrets.
type OTPConfig struct {
	RateLimitDuration time.Duration // Minimum time between OTP generation attempts (default: 1 minute)
	HMACSecret        string        // Required for OTPService: HMAC-SHA256 hashing of OTP codes in storage
}

// SecretConfig configures the optional SecretService. EncryptionKey is only
// required if SecretService is used.
type SecretConfig struct {
	EncryptionKey string // Base64-encoded 32-byte AES-256 key for encrypting secrets
}
