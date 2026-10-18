// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"context"
	"database/sql"
	"time"

	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
)

// Config is the configuration passed to New to construct an AuthKit. The
// DBConnection and the JWT/API-key secrets are required; the remaining fields
// have sensible defaults. See each sub-struct for details.
type Config struct {
	SessionConfig  SessionConfig // Optional; disabled by default, requires migrations 000002 and 000003 when enabled.
	DBConnection   DatabaseConnection
	JWTConfig      JWTConfig
	APIKeyConfig   APIKeyConfig
	PasswordConfig PasswordConfig
	OTPConfig      OTPConfig
	SecretConfig   SecretConfig // Optional: Configuration for SecretService
	// TwoFactorConfig is optional; it turns on two-factor sign-in (TwoFactorService)
	// and requires migration 000009.
	TwoFactorConfig TwoFactorConfig
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
	// reuse, rate-limit rejections/limiter errors, and best-effort write failures).
	// Defaults to a no-op. See the metrics package Counter* constants for the full,
	// authoritative list. Unlike the logger, these survive independently of log
	// level, so they are the recommended basis for alerting.
	Metrics metrics.Metrics

	// VerifyConnectivity, when true, makes New ping both database handles (with a
	// short internal timeout) and fail if either is unreachable, instead of
	// deferring the first connection error to the first query. Off by default so
	// construction stays cheap and offline-testable; turn it on for fail-fast
	// startup, or call AuthKit.Ping from a readiness probe.
	VerifyConnectivity bool

	// RateLimiter is an optional pluggable throttle consulted by AuthService.Login,
	// RefreshToken, OTPService.Generate, and TwoFactorService.CompleteSecondFactor
	// before they do work. It is the
	// recommended place to enforce the IP/global rate limiting the library does not
	// do itself (the per-account lockout is not enough — see SECURITY.md). Defaults
	// to no limiting. See the RateLimiter interface for the key convention.
	RateLimiter RateLimiter

	// RecordSignIns, when true, records every sign-in attempt on an existing
	// account (password logins and VerifiedLoginService.OpenSession, successful or
	// refused) with its method, workspace, session, and the IP address, user agent
	// and device name from SessionInfo. Read it with SignInHistoryService. Off by
	// default. Needs migration 000007. See docs/sign-in-history.md.
	RecordSignIns bool
}

// Aliases of the model package's configuration types, so a Config can be written
// without importing model.
type (
	// SessionMode is how installation sessions are enforced; see SessionConfig.
	SessionMode = model.SessionMode
	// SessionConfig turns on installation-bound sessions (docs/installation-sessions.md).
	SessionConfig = model.SessionConfig

	// SigningKey is the private key JWTConfig.SigningKey signs access tokens with.
	SigningKey = model.SigningKey
	// VerificationKey is a public key JWTConfig.VerificationKeys accepts tokens from.
	VerificationKey = model.VerificationKey
	// JSONWebKey is one public key as a JSON Web Key.
	JSONWebKey = model.JSONWebKey
	// JSONWebKeySet is what AuthKit.JSONWebKeySet returns, to serve at a jwks_uri.
	JSONWebKeySet = model.JSONWebKeySet
)

// The session modes, for SessionConfig.Mode.
const (
	// SessionDisabled is the default: no session tables, refresh tokens only.
	SessionDisabled = model.SessionDisabled
	// SessionOptional allows logins with and without an installation.
	SessionOptional = model.SessionOptional
	// SessionRequired refuses logins that bind no installation.
	SessionRequired = model.SessionRequired
)

// DatabaseConnection holds the PostgreSQL handles and schema for the identity
// store. The read-write and read-only handles may be the same *sql.DB.
type DatabaseConnection struct {
	// Identity schema connections (authkit)
	IdentityRWDB   *sql.DB // For user/session management and audit logging (read-write)
	IdentityRODB   *sql.DB // For auth lookups (SELECT only)
	IdentitySchema string  // Optional PostgreSQL schema name (defaults to authkit)
}

// JWTConfig configures access-token signing and refresh-token hashing.
// RefreshTokenHMACSecret is required, and so is AccessSecret unless SigningKey is
// set; each secret must be at least MinSecretLength bytes of high-entropy random
// data. Expiries default to DefaultAccessExpiry / DefaultRefreshExpiry when zero.
//
// Access tokens are signed with SigningKey when it is set, and otherwise with
// AccessSecret (HS256, no key id). Validation accepts a token with a "kid" header
// only from the key with that id (SigningKey or one of VerificationKeys), and a
// token without one only as HS256 with AccessSecret. AuthKit.JSONWebKeySet
// publishes the public keys. See docs/signing-keys.md for moving off HS256 and
// for rotating keys without logging anyone out.
//
// Note: refresh tokens are opaque random strings, not JWTs — they are not signed,
// only HMAC-hashed (with RefreshTokenHMACSecret) for storage. There is therefore
// no separate refresh-token signing secret.
type JWTConfig struct {
	// AccessSecret is the HS256 secret. With SigningKey set it only validates
	// tokens signed before the switch; remove it once they have expired.
	AccessSecret string
	// SigningKey, when set, signs access tokens with an asymmetric key and stamps
	// its key id. Optional.
	SigningKey *SigningKey
	// VerificationKeys are further public keys whose tokens validate: the next
	// key, published before it signs, or the previous one, until its tokens have
	// expired. Optional.
	VerificationKeys       []VerificationKey
	RefreshTokenHMACSecret string // Secret for HMAC-SHA256 hashing of refresh tokens in storage
	AccessExpiry           time.Duration
	RefreshExpiry          time.Duration
	// RefreshGracePeriod lets a client retry a refresh whose response it lost.
	// Rotation consumes the presented refresh token, and presenting a consumed token
	// again is treated as theft: the family is revoked and the user signed out
	// everywhere. With a grace period, a consumed token can be exchanged again for
	// up to this long, as long as the token that replaced it has never been used; the
	// unused replacement is revoked. Once the replacement has been used, the old token
	// is reuse as before, so whichever of a thief and the owner refreshes second still
	// trips detection. Optional; zero keeps strict rotation. Needs migration 000006.
	// See docs/refresh-tokens.md.
	RefreshGracePeriod time.Duration
	Issuer             string // Optional: if set, stamped as the "iss" claim and required on validation
	Audience           string // Optional: if set, stamped as the "aud" claim and required on validation
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

// SecretConfig configures the optional SecretService, which needs EncryptionKey
// or TenantKey, not both.
type SecretConfig struct {
	EncryptionKey string // Base64-encoded 32-byte AES-256 key for encrypting every tenant's secrets
	// TenantKey, in place of EncryptionKey, gives each tenant a 32-byte AES-256 key of
	// its own, so a key that leaks exposes only its tenant's secrets, and a tenant's
	// secrets are unreadable once its key is destroyed. SecretService calls it for every
	// Save and Get, so keep keys in memory (unwrapping them from a KMS only now and
	// then). Its error comes back from Save and Get, wrapped; a key that is not 32 bytes
	// is ErrSecretEncryptionKeyMissing. Secrets are stored as with EncryptionKey, so
	// returning the old EncryptionKey for each existing tenant keeps what it stored
	// readable. See docs/secrets.md.
	TenantKey func(ctx context.Context, tenantID string) ([]byte, error)
}

// TwoFactorConfig turns on two-factor sign-in with an authenticator app (TOTP)
// and recovery codes. Two-factor is off while EncryptionKey is empty: then no
// login asks for a second factor and TwoFactorService returns
// ErrTwoFactorNotConfigured. Requires migration 000009. See docs/two-factor.md.
type TwoFactorConfig struct {
	// EncryptionKey is a base64-encoded 32-byte random key, used for nothing else
	// (not SecretConfig.EncryptionKey). authkit derives from it the AES-256-GCM key
	// that encrypts authenticator secrets and the HMAC key that recovery codes are
	// stored under. Keep it as you keep your other keys: with a different key, users
	// with two-factor on cannot finish a password login until it is turned off for
	// them (TwoFactorService.Disable).
	EncryptionKey string
	// Issuer names your service in people's authenticator apps, such as "Acme".
	// It is required with EncryptionKey and may not contain a colon.
	Issuer string
}
