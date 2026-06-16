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
	CreateAPIKey(ctx context.Context, req model.CreateAPIKeyRequest) (*model.CreateAPIKeyResponse, error)
	ValidateAPIKey(ctx context.Context, apiKey string) (*model.APIKeyContext, error)
	ListAPIKeys(ctx context.Context, tenantID string, includeExpired bool) ([]*model.APIKey, error)
	GetAPIKey(ctx context.Context, keyID, tenantID string) (*model.APIKey, error)
	RevokeAPIKey(ctx context.Context, keyID, tenantID string) error
	CountByTenant(ctx context.Context, tenantID string) (int, error)
	CleanupExpiredKeys(ctx context.Context) (int64, error)
}

// AuthService provides the end-to-end authentication flows (login, logout, token
// refresh, JWT validation, password change).
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
	CreateInvitation(ctx context.Context, req model.CreateInvitationRequest) (*model.Invitation, error)
	GetInvitation(ctx context.Context, code string) (*model.Invitation, error)
	ValidateInvitation(ctx context.Context, code string) (bool, error)
	AcceptInvitation(ctx context.Context, req model.AcceptInvitationRequest) (uuid.UUID, error)
	ListInvitations(ctx context.Context, tenantID string) ([]*model.Invitation, error)
	ListActiveInvitations(ctx context.Context, tenantID string) ([]*model.Invitation, error)
	RevokeInvitation(ctx context.Context, code string) error
	DeleteInvitation(ctx context.Context, code string) error
	IncrementUseCount(ctx context.Context, code string) error
	CleanupExpiredInvitations(ctx context.Context) (int64, error)
	HasPending(ctx context.Context, email, tenantID string) (bool, error)
}

// JWTService generates and validates JWT access tokens and opaque refresh tokens.
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
	SaveSecret(ctx context.Context, req model.SaveSecretRequest) (*model.SaveSecretResponse, error)
	GetSecret(ctx context.Context, tenantID, key string) (string, error)
	ListSecrets(ctx context.Context, tenantID string) ([]*model.Secret, error)
	DeleteSecret(ctx context.Context, tenantID, key string) error
	MarkVerified(ctx context.Context, tenantID, key string) error
	CountByTenant(ctx context.Context, tenantID string) (int, error)
}

// TenantService manages tenants, their settings, and allowed email domains.
type TenantService interface {
	GetTenant(ctx context.Context, tenantID string) (*model.Tenant, error)
	GetTenantByDomain(ctx context.Context, domain string) (*model.Tenant, error)
	CreateTenant(ctx context.Context, req model.CreateTenantRequest) (*model.Tenant, error)
	// UpdateSettings replaces the tenant's settings, stored as JSONB. The map is
	// an open, application-defined key/value bag (keys are arbitrary strings;
	// values must be JSON-serializable) — the library does not interpret or
	// validate its contents beyond requiring that it marshals to JSON. It is
	// returned verbatim as Tenant.Settings (a map[string]any) by GetTenant.
	UpdateSettings(ctx context.Context, tenantID string, settings map[string]interface{}) error
	UpdateName(ctx context.Context, tenantID, name string) error
	SetAllowedDomains(ctx context.Context, tenantID string, domains []string) error
	AddAllowedDomain(ctx context.Context, tenantID, domain string) error
	ListTenants(ctx context.Context) ([]*model.Tenant, error)
	TenantExists(ctx context.Context, tenantID string) (bool, error)
	ValidateDomainAccess(ctx context.Context, email, tenantID string) error
}

// TokenService provides combined JWT + refresh-token management with rotation.
type TokenService interface {
	GenerateTokenPair(ctx context.Context, user *model.User, sessionInfo *model.SessionInfo) (*model.TokenPairResponse, error)
	ValidateRefreshToken(ctx context.Context, tokenString string) (*model.User, error)
	RefreshTokenPair(ctx context.Context, refreshToken string, sessionInfo *model.SessionInfo) (*model.TokenPairResponse, error)
	RevokeRefreshToken(ctx context.Context, tokenString string) error
	RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error
	CleanupExpiredTokens(ctx context.Context) (int64, error)
}

// UserService manages users, their queries, and account status operations.
type UserService interface {
	Create(ctx context.Context, req model.CreateUserRequest) (uuid.UUID, error)
	Update(ctx context.Context, userID uuid.UUID, tenantID string, req model.UpdateUserRequest) error
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
	CountByTenant(ctx context.Context, tenantID string) (int, error)
	UpdateRolesByTenant(ctx context.Context, userID uuid.UUID, tenantID string, roles []string) error
	EnableByTenant(ctx context.Context, userID uuid.UUID, tenantID string) error
	DisableByTenant(ctx context.Context, userID uuid.UUID, tenantID string) error
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
