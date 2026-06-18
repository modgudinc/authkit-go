// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/internal/service"
	"github.com/modgudinc/authkit-go/model"
)

// The interfaces below are the public contracts for the services returned by
// AuthKit's accessors. They exist so consumers can name the returned values —
// store one on a struct field, pass it to a function, or mock it in a test —
// which the concrete implementations (in an internal package) do not allow. Each
// interface is satisfied by exactly one concrete service; the compile-time
// assertions at the bottom of this file enforce that they stay in sync.

// APIKeyService manages tenant-scoped API keys (creation, validation, revocation).
type APIKeyService interface {
	Create(ctx context.Context, req model.CreateAPIKeyRequest) (*model.CreateAPIKeyResponse, error)
	Validate(ctx context.Context, apiKey string) (*model.APIKeyContext, error)
	List(ctx context.Context, tenantID string, includeExpired bool) ([]*model.APIKey, error)
	Get(ctx context.Context, keyID, tenantID string) (*model.APIKey, error)
	Revoke(ctx context.Context, keyID, tenantID string) error
	Count(ctx context.Context, tenantID string) (int, error)
	CleanupExpired(ctx context.Context) (int64, error)
}

// AuthService provides the end-to-end authentication flows (login, logout, token
// refresh, JWT validation, password change).
//
// Rate limiting is caller-owned. Login enforces only a per-account failed-login
// lockout, which does NOT stop password spraying (a few guesses each across many
// accounts) or distributed guessing, and RefreshToken has no built-in throttle.
// The embedding application MUST add IP-/client-based rate limiting in front of
// these methods. See SECURITY.md ("Caller-Owned Controls").
type AuthService interface {
	Login(ctx context.Context, req model.LoginRequest) (*model.LoginResponse, error)
	Logout(ctx context.Context, refreshToken string) error
	LogoutAll(ctx context.Context, userID uuid.UUID, tenantID string) error
	RefreshToken(ctx context.Context, req model.RefreshRequest) (*model.RefreshResponse, error)
	ValidateJWT(ctx context.Context, token string) (*model.JWTClaims, error)
	ChangePassword(ctx context.Context, req model.ChangePasswordRequest) error
}

// InvitationService manages invitation lifecycle and redemption.
type InvitationService interface {
	Create(ctx context.Context, req model.CreateInvitationRequest) (*model.Invitation, error)
	Get(ctx context.Context, code string) (*model.Invitation, error)
	Validate(ctx context.Context, code string) (bool, error)
	Accept(ctx context.Context, req model.AcceptInvitationRequest) (uuid.UUID, error)
	List(ctx context.Context, tenantID string) ([]*model.Invitation, error)
	ListActive(ctx context.Context, tenantID string) ([]*model.Invitation, error)
	Revoke(ctx context.Context, code string) error
	Delete(ctx context.Context, code string) error
	IncrementUseCount(ctx context.Context, code string) error
	CleanupExpired(ctx context.Context) (int64, error)
	HasPending(ctx context.Context, email, tenantID string) (bool, error)
}

// JWTService generates and validates JWT access tokens and opaque refresh tokens.
//
// GenerateAccessToken copies the supplied *model.User's fields (including
// TokenVersion and Roles) verbatim into the signed claims, so it must be a
// complete, freshly loaded record — a partial/hand-built User can mint a token that
// ValidateJWT treats as revoked. Prefer the AuthService flows, which load the user.
type JWTService interface {
	GenerateAccessToken(user *model.User) (string, error)
	ValidateAccessToken(tokenString string) (*model.JWTClaims, error)
	GenerateRefreshToken() (string, error)
	GetAccessExpiry() time.Duration
	GetRefreshExpiry() time.Duration
}

// OTPService manages one-time verification codes with rate limiting and lockout.
type OTPService interface {
	Generate(ctx context.Context, req model.OTPGenerateRequest) (*model.GenerateResponse, error)
	Validate(ctx context.Context, req model.OTPValidateRequest) error
	Delete(ctx context.Context, tenantID, email, purpose string) error
	CleanupExpired(ctx context.Context) (int64, error)
}

// PasswordService hashes and verifies passwords and validates password strength.
type PasswordService interface {
	HashPassword(password string) (string, error)
	VerifyPassword(password, hash string) error
	DummyVerify(password string)
	ValidatePasswordStrength(password string, requirements model.PasswordStrengthRequirements) error
}

// SecretService manages tenant-scoped encrypted secrets (provider API keys, etc.).
type SecretService interface {
	Save(ctx context.Context, req model.SaveSecretRequest) (*model.SaveSecretResponse, error)
	Get(ctx context.Context, tenantID, key string) (string, error)
	List(ctx context.Context, tenantID string) ([]*model.Secret, error)
	Delete(ctx context.Context, tenantID, key string) error
	MarkVerified(ctx context.Context, tenantID, key string) error
	Count(ctx context.Context, tenantID string) (int, error)
}

// TenantService manages tenants, their settings, and allowed email domains.
//
// Get, GetByDomain, and List return the tenant's full Settings
// map (the application-defined JSONB bag) and apply no caller authorization — they
// are global/admin reads. GetByDomain in particular resolves a tenant from a
// caller-supplied email domain, so do not wire it (or the Settings it returns) into
// an unauthenticated lookup; treat Settings as potentially sensitive.
type TenantService interface {
	Get(ctx context.Context, tenantID string) (*model.Tenant, error)
	GetByDomain(ctx context.Context, domain string) (*model.Tenant, error)
	Create(ctx context.Context, req model.CreateTenantRequest) (*model.Tenant, error)
	// UpdateSettings replaces the tenant's settings, stored as JSONB. The map is
	// an open, application-defined key/value bag (keys are arbitrary strings;
	// values must be JSON-serializable) — the library does not interpret or
	// validate its contents beyond requiring that it marshals to JSON. It is
	// returned verbatim as Tenant.Settings (a map[string]any) by Get.
	UpdateSettings(ctx context.Context, tenantID string, settings map[string]interface{}) error
	UpdateName(ctx context.Context, tenantID, name string) error
	SetAllowedDomains(ctx context.Context, tenantID string, domains []string) error
	AddAllowedDomain(ctx context.Context, tenantID, domain string) error
	List(ctx context.Context) ([]*model.Tenant, error)
	Exists(ctx context.Context, tenantID string) (bool, error)
	ValidateDomainAccess(ctx context.Context, email, tenantID string) error
}

// TokenService provides combined JWT + refresh-token management with rotation.
//
// As with JWTService, GenerateTokenPair stamps the supplied *model.User's fields
// into the access token, so pass a complete, freshly loaded record (see JWTService).
type TokenService interface {
	GenerateTokenPair(ctx context.Context, user *model.User, sessionInfo *model.SessionInfo) (*model.TokenPairResponse, error)
	ValidateRefreshToken(ctx context.Context, tokenString string) (*model.User, error)
	RefreshTokenPair(ctx context.Context, refreshToken string, sessionInfo *model.SessionInfo) (*model.TokenPairResponse, error)
	RevokeRefreshToken(ctx context.Context, tokenString string) error
	// RevokeAllUserTokens is intentionally NOT exposed here: it scopes by user_id
	// only (refresh tokens carry no tenant column), so calling it with a
	// caller-supplied id and no prior tenant-ownership check is a cross-tenant
	// authorization gap. Use AuthService.LogoutAll(ctx, userID, tenantID), which
	// proves tenant membership first and also invalidates access tokens.
	CleanupExpired(ctx context.Context) (int64, error)
}

// UserService manages users, their queries, and account status operations.
//
// Convention: create/update operations take a keyed request struct with the
// identity inside (Create, Update, plus AuthService.ChangePassword); simple
// get/delete/status/role operations take positional ids (userID, tenantID). Every
// mutator is tenant-scoped — a cross-tenant userID matches no row (ErrNotFound).
type UserService interface {
	Create(ctx context.Context, req model.CreateUserRequest) (uuid.UUID, error)
	Update(ctx context.Context, req model.UpdateUserRequest) error
	Delete(ctx context.Context, userID uuid.UUID, tenantID string) error
	GetByID(ctx context.Context, userID uuid.UUID, tenantID string) (*model.User, error)
	GetByEmail(ctx context.Context, email, tenantID string) (*model.User, error)
	Exists(ctx context.Context, email, tenantID string) (bool, error)
	List(ctx context.Context, tenantID string, limit, offset int) ([]*model.User, error)
	ExistsActive(ctx context.Context, email, tenantID string) (bool, error)
	GetDisplayName(ctx context.Context, userID uuid.UUID, tenantID string) (string, error)
	GetActiveUserIDByEmail(ctx context.Context, email, tenantID string) (uuid.UUID, error)
	Enable(ctx context.Context, userID uuid.UUID, tenantID string) error
	Disable(ctx context.Context, userID uuid.UUID, tenantID string) error
	Lock(ctx context.Context, userID uuid.UUID, tenantID string, lockedUntil *time.Time) error
	Unlock(ctx context.Context, userID uuid.UUID, tenantID string) error
	SetPassword(ctx context.Context, userID uuid.UUID, tenantID, hashedPassword string) error
	VerifyPassword(ctx context.Context, userID uuid.UUID, tenantID string) (string, error)
	UpdateLastLogin(ctx context.Context, userID uuid.UUID, tenantID string) error
	IncrementFailedLoginCount(ctx context.Context, userID uuid.UUID, tenantID string) error
	IncrementTokenVersion(ctx context.Context, userID uuid.UUID, tenantID string) error
	UpdateRoles(ctx context.Context, userID uuid.UUID, tenantID string, roles []string) error
	Count(ctx context.Context, tenantID string) (int, error)
}

// Compile-time guarantees that each concrete service satisfies its public
// interface. If a method signature drifts, the build fails here rather than at a
// consumer's call site.
var (
	_ APIKeyService     = (*service.APIKeyService)(nil)
	_ AuthService       = (*service.AuthService)(nil)
	_ InvitationService = (*service.InvitationService)(nil)
	_ JWTService        = (*service.JWTService)(nil)
	_ OTPService        = (*service.OTPService)(nil)
	_ PasswordService   = (*service.PasswordService)(nil)
	_ SecretService     = (*service.SecretService)(nil)
	_ TenantService     = (*service.TenantService)(nil)
	_ TokenService      = (*service.TokenService)(nil)
	_ UserService       = (*service.UserService)(nil)
)
