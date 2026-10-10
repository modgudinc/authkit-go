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
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/internal/service"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
	"github.com/modgudinc/authkit-go/ratelimit"
	"golang.org/x/crypto/bcrypt"
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

	// HighBcryptCostThreshold is the bcrypt cost above which New logs a warning.
	// Costs above ~15 take well over 1s per hash on typical hardware; because every
	// login runs at least one bcrypt comparison (a real one or DummyVerify), an
	// excessive cost is a self-inflicted denial-of-service rather than added safety.
	HighBcryptCostThreshold = 15

	// connectivityCheckTimeout bounds the per-handle ping New issues when
	// Config.VerifyConnectivity is set, so a dead database cannot hang construction.
	connectivityCheckTimeout = 5 * time.Second
)

// AuthKit is the library entrypoint created by New. It is safe for concurrent
// use and holds the configured connections, secrets, and options. Obtain the
// individual services through its accessor methods (AuthService, UserService,
// TokenService, etc.).
type AuthKit struct {
	sessionConfig model.SessionConfig
	rwConnection  *sql.DB
	roConnection  *sql.DB

	accessTokenSecret      string              // HS256; may be empty when accessKeys signs
	accessKeys             *service.AccessKeys // asymmetric signing and verification keys, or nil
	refreshTokenHMACSecret string              // Secret for HMAC-SHA256 hashing of refresh tokens in storage
	jwtIssuer              string              // Optional "iss" claim
	jwtAudience            string              // Optional "aud" claim

	accessTokenExpiry  time.Duration
	refreshTokenExpiry time.Duration
	refreshGrace       time.Duration // JWTConfig.RefreshGracePeriod
	recordSignIns      bool          // Config.RecordSignIns

	apiKeyHMACSecret     string
	passwordBcryptCost   int
	otpRateLimitDuration time.Duration
	otpHMACSecret        string                 // HMAC-SHA256 secret for hashing OTP codes in storage
	secretEncryptionKey  []byte                 // 32-byte AES-256 key for encrypting secrets
	twoFactorKeys        *service.TwoFactorKeys // Config.TwoFactorConfig; nil when two-factor is off
	identitySchema       string
	logger               logger.Logger
	metrics              metrics.Metrics
	rateLimiter          ratelimit.RateLimiter
}

// New validates the Config and returns a configured AuthKit. It fails fast if a
// required connection or secret is missing, a secret is shorter than
// MinSecretLength, a signing or verification key has an unsupported type, curve or
// size or reuses another key's id, the refresh grace period is negative, the
// identity schema is not a valid identifier,
// the secret encryption key (when provided) is not a base64-encoded 32-byte key, or
// the OTP HMAC secret (when provided) is shorter than MinSecretLength. The OTP HMAC secret
// is only required at use time (OTPService.Generate/Validate), not at construction.
func New(config Config) (*AuthKit, error) {
	sessionConfig := config.SessionConfig
	if sessionConfig.Mode > SessionRequired {
		return nil, errors.New("invalid session mode")
	}
	if sessionConfig.AbsoluteLifetime < 0 {
		return nil, errors.New("session absolute lifetime must be positive")
	}
	if sessionConfig.Mode != SessionDisabled {
		if sessionConfig.Namespace == "" || strings.TrimSpace(sessionConfig.Namespace) != sessionConfig.Namespace || strings.ContainsRune(sessionConfig.Namespace, 0) ||
			!utf8.ValidString(sessionConfig.Namespace) || utf8.RuneCountInString(sessionConfig.Namespace) > 255 {
			return nil, errors.New("session namespace must be non-empty and at most 255 characters without surrounding whitespace")
		}
		if sessionConfig.AbsoluteLifetime == 0 {
			sessionConfig.AbsoluteLifetime = 30 * 24 * time.Hour
		}
		if sessionConfig.AbsoluteLifetime < time.Second {
			return nil, errors.New("session absolute lifetime must be at least one second")
		}
	}
	if config.DBConnection.IdentityRWDB == nil {
		return nil, errors.New("RW db connection for identity schema is required")
	}

	if config.DBConnection.IdentityRODB == nil {
		return nil, errors.New("RO db connection for identity schema is required")
	}

	if config.JWTConfig.AccessSecret == "" && config.JWTConfig.SigningKey == nil {
		return nil, errors.New("signing secret or signing key for access tokens is required")
	}
	accessKeys, err := service.NewAccessKeys(config.JWTConfig.SigningKey, config.JWTConfig.VerificationKeys)
	if err != nil {
		return nil, fmt.Errorf("access token keys: %w", err)
	}

	if config.JWTConfig.RefreshTokenHMACSecret == "" {
		return nil, errors.New("HMAC secret for refresh token storage hashing is required")
	}

	if config.APIKeyConfig.HMACSecret == "" {
		return nil, errors.New("HMAC secret for API key hashing is required")
	}

	// Reject weak/short secrets. A short secret silently passes the non-empty
	// checks above but is offline-brute-forceable, allowing token forgery.
	for _, s := range []struct {
		name     string
		value    string
		optional bool
	}{
		{"access token signing secret", config.JWTConfig.AccessSecret, config.JWTConfig.SigningKey != nil},
		{"refresh token HMAC secret", config.JWTConfig.RefreshTokenHMACSecret, false},
		{"API key HMAC secret", config.APIKeyConfig.HMACSecret, false},
	} {
		if s.optional && s.value == "" {
			continue
		}
		if len(s.value) < MinSecretLength {
			return nil, fmt.Errorf("%s must be at least %d bytes of high-entropy random data", s.name, MinSecretLength)
		}
	}

	// OTP HMAC secret is optional at construction (only required when OTPService is
	// used — see OTPConfig.HMACSecret), but if provided it must meet the same
	// entropy bar as the other HMAC secrets. OTPService.Generate/Validate fail with
	// ErrOTPSecretMissing when it is absent.
	if config.OTPConfig.HMACSecret != "" && len(config.OTPConfig.HMACSecret) < MinSecretLength {
		return nil, fmt.Errorf("OTP HMAC secret must be at least %d bytes of high-entropy random data", MinSecretLength)
	}

	identitySchema := config.DBConnection.IdentitySchema
	if identitySchema == "" {
		identitySchema = repository.DefaultIdentitySchema
	}
	if !repository.IsIdentifier(identitySchema) {
		return nil, errors.New("identity schema must be a valid PostgreSQL identifier")
	}

	accessTokenExpiry := DefaultAccessExpiry
	if config.JWTConfig.AccessExpiry > 0 {
		accessTokenExpiry = config.JWTConfig.AccessExpiry
	}

	refreshTokenExpiry := DefaultRefreshExpiry
	if config.JWTConfig.RefreshExpiry > 0 {
		refreshTokenExpiry = config.JWTConfig.RefreshExpiry
	}
	if config.JWTConfig.RefreshGracePeriod < 0 {
		return nil, errors.New("refresh grace period must not be negative")
	}

	// Bcrypt cost: 0 means "unset" and uses the default. A non-zero value outside
	// bcrypt's supported range is rejected (fail fast at construction) rather than
	// silently coerced, so a misconfigured cost surfaces immediately.
	passwordBcryptCost := config.PasswordConfig.BcryptCost
	switch {
	case passwordBcryptCost == 0:
		passwordBcryptCost = service.DefaultBcryptCost
	case passwordBcryptCost < bcrypt.MinCost || passwordBcryptCost > bcrypt.MaxCost:
		return nil, fmt.Errorf("password bcrypt cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
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
			return nil, errors.New("invalid secret encryption key: must be base64 encoded")
		}
		if len(keyBytes) != 32 {
			return nil, errors.New("secret encryption key must be 32 bytes (256 bits)")
		}
		secretEncryptionKey = keyBytes
	}

	twoFactorKeys, err := newTwoFactorKeys(config.TwoFactorConfig)
	if err != nil {
		return nil, err
	}

	// Default to a no-op logger so the library never holds a nil logger and call
	// sites can log unconditionally (a missing nil-guard can no longer panic).
	libLogger := config.Logger
	if libLogger == nil {
		libLogger = logger.NopLogger{}
	}

	// Default to a no-op metrics sink, mirroring the logger default, so the library
	// can increment counters unconditionally.
	libMetrics := config.Metrics
	if libMetrics == nil {
		libMetrics = metrics.NopMetrics{}
	}

	// A very high bcrypt cost is a self-inflicted DoS: PasswordService.DummyVerify
	// runs at this cost on every login (including the unknown-user timing-equalization
	// path), so each attempt burns the corresponding CPU. Warn rather than reject so a
	// deliberately aggressive value still works, but an accidental one surfaces.
	if passwordBcryptCost > HighBcryptCostThreshold {
		libLogger.Warn(context.Background(), "password bcrypt cost is high; every login (including the unknown-user dummy verify) will be correspondingly slow",
			"bcrypt_cost", passwordBcryptCost,
			"suggested_max", HighBcryptCostThreshold,
		)
	}

	kit := &AuthKit{
		sessionConfig: sessionConfig,
		rwConnection:  config.DBConnection.IdentityRWDB,
		roConnection:  config.DBConnection.IdentityRODB,

		accessTokenSecret:      config.JWTConfig.AccessSecret,
		accessKeys:             accessKeys,
		refreshTokenHMACSecret: config.JWTConfig.RefreshTokenHMACSecret,
		jwtIssuer:              config.JWTConfig.Issuer,
		jwtAudience:            config.JWTConfig.Audience,

		accessTokenExpiry:  accessTokenExpiry,
		refreshTokenExpiry: refreshTokenExpiry,
		refreshGrace:       config.JWTConfig.RefreshGracePeriod,
		recordSignIns:      config.RecordSignIns,

		apiKeyHMACSecret:     config.APIKeyConfig.HMACSecret,
		passwordBcryptCost:   passwordBcryptCost,
		otpRateLimitDuration: otpRateLimitDuration,
		otpHMACSecret:        config.OTPConfig.HMACSecret,
		secretEncryptionKey:  secretEncryptionKey,
		twoFactorKeys:        twoFactorKeys,
		identitySchema:       identitySchema,
		logger:               libLogger,
		metrics:              libMetrics,
		rateLimiter:          config.RateLimiter,
	}

	// Optional fail-fast connectivity check (see Config.VerifyConnectivity). Default
	// behavior is unchanged: the first connection error surfaces on the first query.
	if config.VerifyConnectivity {
		ctx, cancel := context.WithTimeout(context.Background(), connectivityCheckTimeout)
		defer cancel()
		if err := kit.Ping(ctx); err != nil {
			return nil, err
		}
	}

	return kit, nil
}

// newTwoFactorKeys checks Config.TwoFactorConfig and derives its keys; nil, nil
// when two-factor is off.
func newTwoFactorKeys(config TwoFactorConfig) (*service.TwoFactorKeys, error) {
	if config.EncryptionKey == "" {
		if config.Issuer != "" {
			return nil, errors.New("two-factor issuer is set without an encryption key")
		}
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(config.EncryptionKey)
	if err != nil {
		return nil, errors.New("invalid two-factor encryption key: must be base64 encoded")
	}
	if len(key) != 32 {
		return nil, errors.New("two-factor encryption key must be 32 bytes (256 bits)")
	}
	issuer := config.Issuer
	if issuer == "" || strings.TrimSpace(issuer) != issuer || strings.ContainsRune(issuer, ':') || !utf8.ValidString(issuer) ||
		utf8.RuneCountInString(issuer) > 255 || strings.ContainsFunc(issuer, unicode.IsControl) {
		return nil, errors.New("two-factor issuer must be 1 to 255 characters without a colon, control characters or surrounding whitespace")
	}
	return service.NewTwoFactorKeys(key, issuer)
}

// Ping verifies connectivity to both the read-write and read-only identity
// databases by issuing a PingContext to each. It is intended for readiness/health
// probes. New performs this check at construction only when
// Config.VerifyConnectivity is set; otherwise connection errors surface lazily on
// the first query.
func (k *AuthKit) Ping(ctx context.Context) error {
	if err := k.rwConnection.PingContext(ctx); err != nil {
		return fmt.Errorf("identity read-write database unreachable: %w", err)
	}
	if err := k.roConnection.PingContext(ctx); err != nil {
		return fmt.Errorf("identity read-only database unreachable: %w", err)
	}
	return nil
}

// JSONWebKeySet returns the public keys that validate access tokens, as a JSON Web
// Key Set (RFC 7517) to serve at a jwks_uri such as /.well-known/jwks.json, so
// other services and API gateways can check tokens without a shared secret. The
// signing key comes first, then JWTConfig.VerificationKeys. The HS256 secret is
// never included: the set is empty for a kit that signs with AccessSecret alone.
//
// A service that checks tokens this way sees only the signature, expiry, issuer
// and audience. It does not see revocation (token versions, disabled accounts,
// revoked sessions): AuthService.ValidateJWT checks those against the database.
func (k *AuthKit) JSONWebKeySet() JSONWebKeySet {
	return k.accessKeys.JSONWebKeySet()
}

// The accessors below each return a service interface. They open no new resources
// — each just wraps the shared connection pool and configuration — but they are not
// free: every call allocates a fresh service (and, for the composite ones like
// AuthService, its whole dependency graph). Prefer constructing a service once and
// reusing it; constructing per call is acceptable but avoid it on hot request paths.
// The returned services are safe for concurrent use.

// APIKeyService returns the API key service
// for managing tenant-scoped API keys (creation, validation, revocation).
func (k *AuthKit) APIKeyService() APIKeyService {
	repo := k.repository()
	return service.NewAPIKeyService(&repo, k.apiKeyHMACSecret, k.logger)
}

// PasswordService returns the password service
// for password hashing and verification using bcrypt.
func (k *AuthKit) PasswordService() PasswordService {
	return k.newPasswordService()
}

// JWTService returns the JWT service
// for generating and validating JWT access tokens and refresh tokens.
func (k *AuthKit) JWTService() JWTService {
	return k.newJWTService()
}

// TokenService returns the token service
// for combined JWT and refresh token management with token rotation.
func (k *AuthKit) TokenService() TokenService {
	return k.newTokenService()
}

// AuthService returns the authentication service
// for complete authentication flows (login, logout, token refresh, JWT validation).
func (k *AuthKit) AuthService() AuthService {
	return k.newAuthService()
}

// InstallationAuthService adds enrollment-bound login and verified bindings.
// Existing AuthService interfaces remain unchanged.
func (k *AuthKit) InstallationAuthService() InstallationAuthService {
	return k.newAuthService()
}

// VerifiedLoginService opens sessions for users the application has verified
// itself (OAuth/OIDC, email links, OTPs, passkeys, device codes). It works in every
// session mode; see docs/verified-sign-in.md.
func (k *AuthKit) VerifiedLoginService() VerifiedLoginService {
	return k.newAuthService()
}

// ExternalIdentityService links accounts at outside sign-in providers (Google,
// GitHub, enterprise OIDC) to users. Requires migration 000004.
func (k *AuthKit) ExternalIdentityService() ExternalIdentityService {
	repo := k.repository()
	return service.NewExternalIdentityService(&repo, k.logger, k.metrics)
}

// PasskeyService stores WebAuthn credentials (passkeys and security keys) and the
// user handles they carry; the application runs the WebAuthn ceremonies. Requires
// migration 000008; see docs/passkeys.md.
func (k *AuthKit) PasskeyService() PasskeyService {
	repo := k.repository()
	return service.NewPasskeyService(&repo, k.logger, k.metrics)
}

// TwoFactorService sets up two-factor sign-in with an authenticator app and
// recovery codes, and finishes the password logins that wait for a second factor.
// Requires Config.TwoFactorConfig (without it every call returns
// ErrTwoFactorNotConfigured) and migration 000009; see docs/two-factor.md.
func (k *AuthKit) TwoFactorService() TwoFactorService {
	repo := k.repository()
	return service.NewTwoFactorService(&repo, k.newAuthService(), k.twoFactorKeys, k.logger, k.metrics)
}

// SessionService manages sessions scoped to the configured application namespace.
// Callers must authorize session-management actions for the supplied user.
func (k *AuthKit) SessionService() SessionService {
	repo := k.repository()
	return service.NewSessionService(&repo, k.sessionConfig, k.logger)
}

// SignInHistoryService reads the sign-in history that Config.RecordSignIns
// records. Requires migration 000007; see docs/sign-in-history.md.
func (k *AuthKit) SignInHistoryService() SignInHistoryService {
	repo := k.repository()
	return service.NewSignInHistoryService(&repo, k.logger)
}

func (k *AuthKit) newAuthService() *service.AuthService {
	repo := k.repository()
	var opts []service.AuthOption
	if k.recordSignIns {
		opts = append(opts, service.WithSignInHistory(&repo, k.sessionConfig.Namespace))
	}
	if k.twoFactorKeys != nil {
		opts = append(opts, service.WithTwoFactor(&repo, k.twoFactorKeys))
	}
	return service.NewAuthService(&repo, k.newPasswordService(), k.newTokenService(), k.newJWTService(), k.logger, k.metrics, k.rateLimiter, opts...)
}

// newPasswordService / newJWTService / newTokenService return the concrete
// services for internal composition. The public accessors above expose them as
// interfaces; the internal constructors still wire concrete types together.
func (k *AuthKit) newPasswordService() *service.PasswordService {
	return service.NewPasswordService(k.passwordBcryptCost, k.logger)
}

func (k *AuthKit) newJWTService() *service.JWTService {
	return service.NewJWTService(
		k.accessTokenSecret,
		k.accessTokenExpiry,
		k.refreshTokenExpiry,
		k.logger,
		service.WithIssuer(k.jwtIssuer),
		service.WithAudience(k.jwtAudience),
		service.WithSessionMode(k.sessionConfig.Mode),
		service.WithAccessKeys(k.accessKeys),
	)
}

func (k *AuthKit) newTokenService() *service.TokenService {
	repo := k.repository()
	return service.NewTokenService(&repo, k.newJWTService(), k.refreshTokenExpiry, k.refreshTokenHMACSecret, k.logger, k.metrics,
		service.WithTokenSessions(k.sessionConfig), service.WithRefreshGracePeriod(k.refreshGrace))
}

// OTPService returns the OTP service
// for OTP generation, validation, and lifecycle management with rate limiting.
func (k *AuthKit) OTPService() OTPService {
	repo := k.repository()
	return service.NewOTPService(&repo, k.otpRateLimitDuration, k.otpHMACSecret, k.logger, k.metrics, k.rateLimiter)
}

// TenantService returns the tenant service
// for tenant management, settings, and domain validation.
func (k *AuthKit) TenantService() TenantService {
	repo := k.repository()
	return service.NewTenantService(&repo, k.logger)
}

// InvitationService returns the invitation service
// for invitation management, validation, and lifecycle operations.
func (k *AuthKit) InvitationService() InvitationService {
	repo := k.repository()
	return service.NewInvitationService(&repo, k.logger)
}

// SecretService returns the secret service
// for managing encrypted secrets (provider API keys, etc.).
//
// IMPORTANT: SecretConfig.EncryptionKey must be configured for this service to work.
// The encryption key must be a base64-encoded 32-byte (256-bit) key. Operations
// return ErrSecretEncryptionKeyMissing if it is absent or the wrong length.
func (k *AuthKit) SecretService() SecretService {
	repo := k.repository()
	return service.NewSecretService(&repo, k.secretEncryptionKey, k.logger)
}

// UserService returns the user service
// for global-identity management, queries, and account status operations.
func (k *AuthKit) UserService() UserService {
	repo := k.repository()
	return service.NewUserService(&repo, k.logger, service.WithUserSessions(k.sessionConfig.Mode != SessionDisabled))
}

// MembershipService returns the membership service
// for managing the user<->tenant membership graph (grant/revoke, roles, member lists).
func (k *AuthKit) MembershipService() MembershipService {
	repo := k.repository()
	return service.NewMembershipService(&repo, k.logger)
}

func (k *AuthKit) repository() repository.Repository {
	return repository.NewWithSchema(k.rwConnection, k.roConnection, k.identitySchema)
}
