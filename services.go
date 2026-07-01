// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"context"
	"time"

	"github.com/modgudinc/authkit-go/internal/service"
	"github.com/modgudinc/authkit-go/model"
	"github.com/modgudinc/authkit-go/ratelimit"
)

// RateLimiter is the optional throttle injected via Config.RateLimiter. It is an
// alias for ratelimit.RateLimiter so callers can refer to authkit.RateLimiter.
type RateLimiter = ratelimit.RateLimiter

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
	// Login authenticates into a known workspace (req.TenantID) and returns a
	// workspace-scoped access token + identity-session refresh token.
	Login(ctx context.Context, req model.LoginRequest) (*model.LoginResponse, error)
	// LoginByEmail authenticates the identity without a known workspace: it opens the
	// session and either mints a token (when the workspace is given or the identity
	// has exactly one active membership) or returns the membership list to choose from.
	LoginByEmail(ctx context.Context, req model.LoginByEmailRequest) (*model.LoginResponse, error)
	// MintWorkspaceToken mints a fresh workspace-scoped access token from an existing
	// identity session (the refresh token) — the select-/switch-workspace call.
	MintWorkspaceToken(ctx context.Context, refreshToken, tenantID string) (*model.WorkspaceTokenResponse, error)
	Logout(ctx context.Context, refreshToken string) error
	// LogoutAll invalidates every workspace's access tokens and revokes all refresh
	// tokens for an identity (identity-level; the caller authorizes userID).
	LogoutAll(ctx context.Context, userID string) error
	RefreshToken(ctx context.Context, req model.RefreshRequest) (*model.RefreshResponse, error)
	ValidateJWT(ctx context.Context, token string) (*model.JWTClaims, error)
	ChangePassword(ctx context.Context, req model.ChangePasswordRequest) error
}

// MembershipService manages the user<->tenant membership graph: which global
// identity belongs to which tenant, with which (opaque) roles. authkit owns the
// graph; the embedding application interprets the role strings. Remove is a
// soft-revoke (the membership is suspended and its token_version bumped); Add is an
// idempotent upsert that re-grants/reactivates.
type MembershipService interface {
	Add(ctx context.Context, req model.AddMembershipRequest) error
	Remove(ctx context.Context, userID, tenantID string) error
	UpdateRoles(ctx context.Context, userID, tenantID string, roles []string) error
	Get(ctx context.Context, userID, tenantID string) (*model.Membership, error)
	ListByUser(ctx context.Context, userID string) ([]*model.Membership, error)
	ListByTenant(ctx context.Context, tenantID string) ([]*model.Membership, error)
	CountByTenant(ctx context.Context, tenantID string) (int, error)
}

// InvitationService manages invitation lifecycle and redemption.
//
// The by-code operations (Get, Validate, Accept, Revoke, Delete, IncrementUseCount)
// are keyed only by the invitation code, which is a high-entropy (~103-bit),
// non-enumerable bearer capability — possession of the code is the authorization to
// act on it, and the library does NOT additionally check the caller's tenant. Accept
// derives the new user's tenant and roles from the invitation row (not from caller
// input), so there is no privilege escalation. If your model requires that an admin
// may only manage invitations within their own tenant, resolve the code first with
// Get and check the returned TenantID before calling Revoke/Delete/IncrementUseCount.
type InvitationService interface {
	Create(ctx context.Context, req model.CreateInvitationRequest) (*model.Invitation, error)
	Get(ctx context.Context, code string) (*model.Invitation, error)
	Validate(ctx context.Context, code string) (bool, error)
	Accept(ctx context.Context, req model.AcceptInvitationRequest) (userID string, created bool, err error)
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
// GenerateAccessToken copies the supplied user's identity fields (TokenVersion) and
// the membership's workspace fields (TenantID, Roles, membership TokenVersion)
// verbatim into the signed claims, so both must be complete, freshly loaded records —
// a partial/hand-built record can mint a token that ValidateJWT treats as revoked.
// Prefer the AuthService flows, which load both.
type JWTService interface {
	GenerateAccessToken(user *model.User, membership *model.Membership) (string, error)
	ValidateAccessToken(tokenString string) (*model.JWTClaims, error)
	GenerateRefreshToken() (string, error)
	GetAccessExpiry() time.Duration
	GetRefreshExpiry() time.Duration
}

// OTPService manages one-time verification codes with rate limiting and lockout.
type OTPService interface {
	Generate(ctx context.Context, req model.OTPGenerateRequest) (*model.GenerateResponse, error)
	Validate(ctx context.Context, req model.OTPValidateRequest) error
	Delete(ctx context.Context, email, purpose string) error
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
	GenerateTokenPair(ctx context.Context, user *model.User, membership *model.Membership, sessionInfo *model.SessionInfo) (*model.TokenPairResponse, error)
	ValidateRefreshToken(ctx context.Context, tokenString string) (*model.User, error)
	RefreshTokenPair(ctx context.Context, refreshToken string, tenantID string, sessionInfo *model.SessionInfo) (*model.TokenPairResponse, error)
	RevokeRefreshToken(ctx context.Context, tokenString string) error
	// RevokeAllUserTokens is intentionally NOT exposed here: it revokes every refresh
	// token for a user id without any authorization check. Use AuthService.LogoutAll(ctx,
	// userID), which is identity-level — it bumps the identity token_version (invalidating
	// every workspace's access tokens) and then revokes the user's refresh tokens; the
	// caller is responsible for authorizing that it may act on userID.
	CleanupExpired(ctx context.Context) (int64, error)
}

// UserService manages GLOBAL identities, their queries, and account status
// operations. A user carries no tenant or roles (those live on memberships — see
// MembershipService); every operation is keyed by the global user id or the
// globally-unique email.
//
// Convention: create/update operations take a keyed request struct with the identity
// inside (Create, Update, plus AuthService.ChangePassword); simple get/delete/status
// operations take a positional userID (or email for lookups).
type UserService interface {
	Create(ctx context.Context, req model.CreateUserRequest) (string, error)
	Update(ctx context.Context, req model.UpdateUserRequest) error
	Delete(ctx context.Context, userID string) error
	GetByID(ctx context.Context, userID string) (*model.User, error)
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	Exists(ctx context.Context, email string) (bool, error)
	// List is a global (cross-tenant) admin listing; for a tenant's members use
	// MembershipService.ListByTenant.
	List(ctx context.Context, limit, offset int) ([]*model.User, error)
	ExistsActive(ctx context.Context, email string) (bool, error)
	GetDisplayName(ctx context.Context, userID string) (string, error)
	GetActiveUserIDByEmail(ctx context.Context, email string) (string, error)
	Enable(ctx context.Context, userID string) error
	Disable(ctx context.Context, userID string) error
	Lock(ctx context.Context, userID string, lockedUntil *time.Time) error
	Unlock(ctx context.Context, userID string) error
	SetPassword(ctx context.Context, userID, hashedPassword string) error
	VerifyPassword(ctx context.Context, userID string) (string, error)
	UpdateLastLogin(ctx context.Context, userID string) error
	IncrementFailedLoginCount(ctx context.Context, userID string) error
	IncrementTokenVersion(ctx context.Context, userID string) error
	// StatusHistory returns a user's account status-change audit trail (newest
	// first). CleanupStatusChanges deletes audit rows older than olderThan (which must
	// be positive) and returns the count removed; run it periodically to bound the
	// otherwise unbounded audit table.
	StatusHistory(ctx context.Context, userID string) ([]*model.UserStatusChange, error)
	CleanupStatusChanges(ctx context.Context, olderThan time.Duration) (int64, error)
}

// Compile-time guarantees that each concrete service satisfies its public
// interface. If a method signature drifts, the build fails here rather than at a
// consumer's call site.
var (
	_ APIKeyService     = (*service.APIKeyService)(nil)
	_ AuthService       = (*service.AuthService)(nil)
	_ InvitationService = (*service.InvitationService)(nil)
	_ JWTService        = (*service.JWTService)(nil)
	_ MembershipService = (*service.MembershipService)(nil)
	_ OTPService        = (*service.OTPService)(nil)
	_ PasswordService   = (*service.PasswordService)(nil)
	_ SecretService     = (*service.SecretService)(nil)
	_ TenantService     = (*service.TenantService)(nil)
	_ TokenService      = (*service.TokenService)(nil)
	_ UserService       = (*service.UserService)(nil)
)
