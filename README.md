# authkit-go

A Go library for multi-tenant identity and authentication management with support for API key authentication, invitation-based user onboarding, and OTP verification.

[![Go Version](https://img.shields.io/badge/go-1.25-blue.svg)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

## Features

- **Multi-Tenant Architecture**: Tenant-scoped user management with role-based access control (Admin, Member, Viewer)
- **API Key Management**: Secure API key generation and validation with HMAC-SHA256 hashing
- **Invitation System**: Invitation-based user onboarding with secure access codes
- **OTP Verification**: One-Time Password generation and email verification
- **Security-First**: Cryptographically secure random generation, one-way hashing, UUID v7 identifiers
- **Flexible Logging**: Dependency injection for logger implementation
- **Read-Write Separation**: Optimized database connection management

## Installation

```bash
go get github.com/modgudinc/authkit-go
```

## Documentation

- [Architecture, data model, and security assumptions](docs/architecture.md)
- [Service examples](docs/examples.md)
- [Common patterns](docs/patterns.md)
- [Troubleshooting](docs/troubleshooting.md)

## Quick Start

### 1. Initialize the Library

```go
package main

import (
	"database/sql"
	"log"
	"os"
	"time"

    authkit "github.com/modgudinc/authkit-go"
    _ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver (pgx, database/sql-compatible)
)

func main() {
    // Set up database connections (database/sql with the pgx driver).
    rwDB, err := sql.Open("pgx", os.Getenv("RW_DATABASE_URL"))
    if err != nil {
        log.Fatal(err)
    }
    defer rwDB.Close()

    roDB, err := sql.Open("pgx", os.Getenv("RO_DATABASE_URL"))
    if err != nil {
        log.Fatal(err)
    }
    defer roDB.Close()

    // Initialize the library
    identity, err := authkit.New(authkit.Config{
        DBConnection: authkit.DatabaseConnection{
            IdentityRWDB: rwDB,
            IdentityRODB: roDB,
            IdentitySchema: "authkit", // Optional, defaults to authkit
        },
        JWTConfig: authkit.JWTConfig{
            AccessSecret:           os.Getenv("JWT_ACCESS_SECRET"),
            RefreshSecret:          os.Getenv("JWT_REFRESH_SECRET"),
            RefreshTokenHMACSecret: os.Getenv("REFRESH_TOKEN_HMAC_SECRET"), // Required
            AccessExpiry:           time.Minute * 15,  // Optional, defaults to 15 minutes
            RefreshExpiry:          time.Hour * 168,   // Optional, defaults to 7 days
        },
        APIKeyConfig: authkit.APIKeyConfig{
            HMACSecret: os.Getenv("API_KEY_HMAC_SECRET"), // Required
        },
        PasswordConfig: authkit.PasswordConfig{
            BcryptCost: 12, // Optional, defaults to 12
        },
        OTPConfig: authkit.OTPConfig{
            RateLimitDuration: time.Minute * 1, // Optional, defaults to 1 minute
        },
        Logger: nil, // Optional: inject your logger (zap, logrus, etc.)
    })
    if err != nil {
        log.Fatal(err)
    }

    // Use the library
    apiKeyService := identity.APIKeyService()
    // ... use services
}
```

Each accessor (`AuthService()`, `UserService()`, `APIKeyService()`, …) returns a
named **interface** from package `authkit`, so you can store it on a struct, pass
it to a function, or mock it in a test:

```go
type Handlers struct {
    auth authkit.AuthService // a named type you can hold and mock
}

h := Handlers{auth: identity.AuthService()}
```

The returned services are cheap to construct (they wrap the shared connection
pool and config), so calling an accessor per use or caching one is equally fine.

### 2. Custom Logger Implementation

Implement the `Logger` interface to integrate with your logging library:

```go
import "go.uber.org/zap"

// ZapLogger wraps zap.Logger to implement authkit.Logger
type ZapLogger struct {
    logger *zap.Logger
}

func (z *ZapLogger) Debug(msg string, fields ...interface{}) {
    z.logger.Sugar().Debugw(msg, fields...)
}

func (z *ZapLogger) Info(msg string, fields ...interface{}) {
    z.logger.Sugar().Infow(msg, fields...)
}

func (z *ZapLogger) Error(msg string, fields ...interface{}) {
    z.logger.Sugar().Errorw(msg, fields...)
}

func (z *ZapLogger) Warn(msg string, fields ...interface{}) {
    z.logger.Sugar().Warnw(msg, fields...)
}

// Use it
zapLogger, _ := zap.NewProduction()
logger := &ZapLogger{logger: zapLogger}

identity, err := authkit.New(authkit.Config{
    // ... other config
    Logger: logger,
})
```

> **PII in logs:** authkit masks sensitive values before logging — email addresses
> are emitted as `u***@acme.com`, OTP/invitation codes are truncated, and secrets
> are never logged. Logs are treated as a hostile surface (see
> [SECURITY.md](SECURITY.md)); keep this in mind for your own log lines.

## API Key Management

### Create an API Key

```go
apiKeyService := identity.APIKeyService()

expiresIn := 90 * 24 * time.Hour // Optional: expires in 90 days (nil = never)
response, err := apiKeyService.CreateAPIKey(ctx, model.CreateAPIKeyRequest{
    TenantID:  "acme.com",
    CreatedBy: adminUserID, // uuid.UUID of the admin (FK to users.id)
    Name:      "Production SDK Key",
    ExpiresIn: &expiresIn, // Optional
})
if err != nil {
    log.Fatal(err)
}

// IMPORTANT: The API key is only returned once
fmt.Printf("API Key: %s\n", response.APIKey)
fmt.Printf("Key ID: %s\n", response.KeyID)
```

**API Key Format**: `sk_live_<32-random-chars>` (40 characters total)

### Validate an API Key

```go
apiKey := "sk_live_abc123..." // From HTTP header or SDK

keyCtx, err := apiKeyService.ValidateAPIKey(ctx, apiKey)
if err != nil {
    // Invalid or expired key
    return err
}

// Use tenant context
fmt.Printf("Tenant ID: %s\n", keyCtx.TenantID)
fmt.Printf("Key ID: %s\n", keyCtx.KeyID)
```

### List API Keys

```go
// List all non-expired keys
apiKeys, err := apiKeyService.ListAPIKeys(ctx, "acme.com", false)
if err != nil {
    log.Fatal(err)
}

// List including expired keys
allKeys, err := apiKeyService.ListAPIKeys(ctx, "acme.com", true)
```

### Revoke an API Key

The revoke (and `GetAPIKey`) lookup is scoped to the owning tenant, so pass the
tenant ID alongside the key ID. This prevents one tenant from revoking or reading
another tenant's key by guessing its ID.

```go
err := apiKeyService.RevokeAPIKey(ctx, "key-uuid-v7", "acme.com")
if err != nil {
    log.Fatal(err)
}
```

### Cleanup Expired Keys

Run periodically (e.g., via cron job) to maintain database hygiene:

```go
count, err := apiKeyService.CleanupExpiredKeys(ctx)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Deleted %d expired keys\n", count)
```

## Password Management

### Hash a Password

```go
passwordService := identity.PasswordService()

// Hash password before storing in database
hash, err := passwordService.HashPassword("SecurePassword123!")
if err != nil {
    log.Fatal(err)
}

// Store hash in database (NEVER store plaintext)
// user.PasswordHash = hash
```

### Verify a Password

```go
// During login - compare user input with stored hash
err := passwordService.VerifyPassword(userInputPassword, user.PasswordHash)
if err != nil {
    // Password is incorrect
    return fmt.Errorf("invalid credentials")
}

// Password is correct - proceed with authentication
```

### Validate Password Strength (Optional)

```go
// Use default requirements (min 8 chars, upper, lower, digit, special)
requirements := model.DefaultPasswordRequirements()

err := passwordService.ValidatePasswordStrength(userPassword, requirements)
if err != nil {
    // Return validation errors to user
    return err
}
```

### Custom Password Requirements

```go
customReqs := model.PasswordStrengthRequirements{
    MinLength:      10,
    RequireUpper:   true,
    RequireLower:   true,
    RequireNumber:  true,
    RequireSpecial: false, // Don't require special characters
}

err := passwordService.ValidatePasswordStrength(password, customReqs)
```

## JWT Token Management

### Generate Access Token

```go
jwtService := identity.JWTService()

// Generate JWT for authenticated user
accessToken, err := jwtService.GenerateAccessToken(user)
if err != nil {
    log.Fatal(err)
}

// Return token to client (e.g., in HTTP response)
```

**JWT contains custom claims:**
- `user_id` - User UUID (string)
- `email` - User email address
- `tenant_id` - Tenant identifier
- `roles` - Array of user roles
- `token_version` - For invalidating all tokens
- Standard claims (sub, iat, exp)

### Validate Access Token

```go
// Extract token from HTTP header (e.g., Authorization: Bearer <token>)
tokenString := req.Header.Get("Authorization")

claims, err := jwtService.ValidateAccessToken(tokenString)
if err != nil {
    // Token is invalid or expired
    return fmt.Errorf("unauthorized: %w", err)
}

// Use claims for authorization
userID := claims.UserID          // User UUID
email := claims.Email            // User email
tenantID := claims.TenantID      // Tenant ID
roles := claims.Roles            // []string
tokenVersion := claims.TokenVersion // For invalidation
```

### Generate Refresh Token

```go
// Generate cryptographically secure random token (NOT a JWT)
refreshToken, err := jwtService.GenerateRefreshToken()
if err != nil {
    log.Fatal(err)
}

// Store HMAC-SHA256(refreshToken) in database (via TokenService)
// Return plaintext refreshToken to client (only time it's visible)
// Refresh tokens are 32 bytes = 44 base64 characters
```

**Note:** Refresh tokens are random tokens stored in the database with HMAC-SHA256 hash (for defense in depth), not JWTs. This enables single-use refresh tokens and rotation.

### Complete Login Flow Example

```go
// 1. Verify password
passwordService := identity.PasswordService()
err := passwordService.VerifyPassword(inputPassword, user.PasswordHash)
if err != nil {
    return fmt.Errorf("invalid credentials")
}

// 2. Generate JWT access token
jwtService := identity.JWTService()
accessToken, err := jwtService.GenerateAccessToken(user)

// 3. Generate refresh token
refreshToken, err := jwtService.GenerateRefreshToken()

// 4. Store refresh token hash in database with expiry
// refreshTokenHash := sha256Hash(refreshToken)
// Save refreshTokenHash to database

// 5. Return tokens to client
return LoginResponse{
    AccessToken:  accessToken,
    RefreshToken: refreshToken,
    ExpiresIn:    int64(jwtService.GetAccessExpiry().Seconds()),
}
```

## Token Service (Combined JWT + Refresh Token Management)

The TokenService combines JWT and refresh token management with automatic token rotation.

### Generate Token Pair

```go
tokenService := identity.TokenService()

// Generate both access token (JWT) and refresh token
tokenPair, err := tokenService.GenerateTokenPair(ctx, user, &model.SessionInfo{
    IPAddress:  "192.168.1.1",
    UserAgent:  "Mozilla/5.0...",
    DeviceName: "Chrome Browser",
})
if err != nil {
    log.Fatal(err)
}

// Return both tokens to client
// Access token: JWT for API authentication
// Refresh token: Random token stored as HMAC-SHA256 hash (for token rotation)
```

### Refresh Token Pair (Token Rotation)

```go
// Client sends current refresh token to get new tokens
newTokenPair, err := tokenService.RefreshTokenPair(ctx, oldRefreshToken, sessionInfo)
if err != nil {
    log.Fatal(err)
}

// Both tokens are NEW - old refresh token is automatically revoked
// Client must replace BOTH access token and refresh token
```

**Token Rotation Flow:**
1. Client sends current refresh token
2. Server atomically consumes the current refresh token
3. New refresh token is stored in the same transaction
4. New access token (JWT) is generated
5. If the old refresh token is missing, expired, or already consumed, rotation fails
6. Client receives both new tokens

### Revoke Refresh Tokens

```go
// Revoke specific refresh token (single session logout)
err := tokenService.RevokeRefreshToken(ctx, refreshToken)

// Revoke all refresh tokens for user (logout from all devices)
err := tokenService.RevokeAllUserTokens(ctx, userID)

// Cleanup expired tokens (periodic maintenance job)
count, err := tokenService.CleanupExpiredTokens(ctx)
fmt.Printf("Deleted %d expired tokens\n", count)
```

## Authentication Service

The AuthService provides complete authentication flows integrating password verification, JWT generation, and token management.

### Login

```go
authService := identity.AuthService()

response, err := authService.Login(ctx, model.LoginRequest{
    Email:    "user@acme.com",
    Password: "SecurePassword123!",
    TenantID: "acme.com",
    SessionInfo: &model.SessionInfo{
        IPAddress:  "192.168.1.1",
        UserAgent:  "Mozilla/5.0...",
        DeviceName: "Chrome Browser",
    },
})
if err != nil {
    // Handle errors: invalid credentials, account disabled, account locked
    log.Fatal(err)
}

// Return tokens and user info to client
fmt.Printf("Access Token: %s\n", response.AccessToken)
fmt.Printf("Refresh Token: %s\n", response.RefreshToken)
fmt.Printf("Expires In: %d seconds\n", response.ExpiresIn)
fmt.Printf("User: %+v\n", response.User)
```

**Login Features:**
- Password verification with bcrypt
- Account status checks (enabled, not locked)
- Auto-unlock if `locked_until` has passed
- Failed login tracking (locks after 5 attempts for 30 minutes)
- Last login timestamp updates
- Automatic token pair generation with session tracking

### Logout

```go
// Single session logout (revoke specific refresh token)
err := authService.Logout(ctx, refreshToken)
// Note: JWT remains valid until expiry (stateless design)

// Logout from all devices (revoke all tokens + invalidate all JWTs)
err := authService.LogoutAll(ctx, userID)
// This increments token_version, immediately invalidating all existing JWTs
```

### Token Refresh

```go
response, err := authService.RefreshToken(ctx, model.RefreshRequest{
    RefreshToken: oldRefreshToken,
    SessionInfo:  sessionInfo,
})
if err != nil {
    // Refresh token invalid or expired - require re-login
    log.Fatal(err)
}

// Return new tokens (old refresh token is automatically revoked)
fmt.Printf("New Access Token: %s\n", response.AccessToken)
fmt.Printf("New Refresh Token: %s\n", response.RefreshToken)
```

### JWT Validation

```go
claims, err := authService.ValidateJWT(ctx, tokenString)
if err != nil {
    // Token invalid, expired, revoked, or account disabled/locked
    return fmt.Errorf("unauthorized: %w", err)
}

// Use claims for authorization
userID := claims.UserID      // User UUID
email := claims.Email        // User email
tenantID := claims.TenantID  // Tenant ID
roles := claims.Roles        // User roles ([]string)
```

**Validation Features:**
- JWT signature and expiration verification
- Token version check (detect revoked tokens)
- Account enabled check
- Account locked check (with auto-unlock)
- Returns enriched claims

### Change Password

```go
err := authService.ChangePassword(ctx, model.ChangePasswordRequest{
    UserID:      userID,
    OldPassword: "OldPassword123!",
    NewPassword: "NewSecurePassword456!",
})
if err != nil {
    // Old password incorrect or new password validation failed
    log.Fatal(err)
}

// Password changed successfully
// All sessions invalidated (user must re-login on all devices)
```

**Password Change Features:**
- Old password verification
- New password strength validation
- Automatic logout from all devices (token version increment)
- All refresh tokens revoked

## Tenant Service

The TenantService provides tenant management operations including creation, retrieval, settings management, and domain management.

### Get Tenant

```go
tenantService := identity.TenantService()

// Retrieve tenant by tenant_id (primary email domain)
tenant, err := tenantService.GetTenant(ctx, "acme.com")
if err != nil {
    log.Fatal(err)
}

// Access tenant data
fmt.Printf("Tenant: %s\n", tenant.Name)
fmt.Printf("Allowed Domains: %v\n", tenant.AllowedDomains)
```

### Create Tenant

```go
// Create new tenant/organization
tenant, err := tenantService.CreateTenant(ctx, model.CreateTenantRequest{
    TenantID:       "acme.com",                    // Primary email domain
    Name:           "Acme Corporation",
    AllowedDomains: []string{"acme.com", "acme.io"}, // Multi-domain support
})
if err != nil {
    log.Fatal(err)
}

// Tenant created successfully
fmt.Printf("Created tenant: %s\n", tenant.TenantID)
```

**Creation Features:**
- Domain format validation (ensures valid email domain pattern)
- Multi-domain validation (validates all allowed_domains)
- Automatic timestamps (created_at, updated_at)
- Retrieves created tenant after insertion

### Update Tenant Settings

```go
// Update tenant settings (stored as JSONB)
settings := map[string]interface{}{
    "features": map[string]interface{}{
        "api_access":     true,
        "export_data":    true,
        "custom_branding": false,
    },
    "limits": map[string]interface{}{
        "max_users":   100,
        "max_api_keys": 10,
    },
}

err := tenantService.UpdateSettings(ctx, "acme.com", settings)
if err != nil {
    log.Fatal(err)
}

// Settings updated successfully
```

**Settings Features:**
- JSON validation before storage
- Flexible schema (any valid JSON structure)
- Automatic marshaling to JSONB
- Atomic updates with timestamp tracking

### Add Allowed Domain

```go
// Add additional email domain to tenant
err := tenantService.AddAllowedDomain(ctx, "acme.com", "acme.io")
if err != nil {
    // Domain already exists or invalid format
    log.Fatal(err)
}

// Domain added successfully (duplicates prevented automatically)
```

**Domain Management Features:**
- Domain format validation (ensures valid email domain)
- Duplicate prevention (database-level check)
- Supports subdomains (e.g., "mail.acme.com")
- Automatic timestamp updates

### List Tenants

```go
// List all tenants (admin/debug operation)
tenants, err := tenantService.ListTenants(ctx)
if err != nil {
    log.Fatal(err)
}

// Tenants ordered by created_at DESC (newest first)
for _, tenant := range tenants {
    fmt.Printf("Tenant: %s (%s)\n", tenant.Name, tenant.TenantID)
}
```

### Check Tenant Existence

```go
// Check if tenant exists before operations
exists, err := tenantService.TenantExists(ctx, "acme.com")
if err != nil {
    log.Fatal(err)
}

if !exists {
    return fmt.Errorf("tenant not found")
}
```

### Validate Domain Access

```go
// Validate that an email domain is allowed for a tenant
err := tenantService.ValidateDomainAccess(ctx, "user@acme.io", "acme.com")
if err != nil {
    // Email domain not allowed for this tenant
    return fmt.Errorf("access denied: %w", err)
}

// Email domain is allowed - proceed with operation
```

**Validation Features:**
- Extracts domain from email address
- Checks against tenant's allowed_domains list
- Case-insensitive domain matching
- Used for signup validation and access control

### Complete Multi-Tenant Signup Example

```go
// Step 1: Validate email domain is allowed for tenant
func ValidateSignupEmail(ctx context.Context, email, tenantID string) error {
    tenantService := identity.TenantService()

    // Check if domain is allowed for tenant
    err := tenantService.ValidateDomainAccess(ctx, email, tenantID)
    if err != nil {
        return fmt.Errorf("email domain not allowed: %w", err)
    }

    return nil
}

// Step 2: Multi-domain tenant creation during admin signup
func CreateTenantWithMultipleDomains(ctx context.Context, primaryDomain, name string, additionalDomains []string) error {
    tenantService := identity.TenantService()

    // Create tenant with all allowed domains
    allDomains := append([]string{primaryDomain}, additionalDomains...)

    tenant, err := tenantService.CreateTenant(ctx, model.CreateTenantRequest{
        TenantID:       primaryDomain,
        Name:           name,
        AllowedDomains: allDomains,
    })
    if err != nil {
        return fmt.Errorf("failed to create tenant: %w", err)
    }

    // Configure initial settings
    defaultSettings := map[string]interface{}{
        "features": map[string]interface{}{
            "api_access": true,
            "export_data": false,
        },
    }

    err = tenantService.UpdateSettings(ctx, tenant.TenantID, defaultSettings)
    if err != nil {
        return fmt.Errorf("failed to update settings: %w", err)
    }

    return nil
}
```

**Tenant Characteristics:**
- **Multi-domain support** (organizations can register multiple email domains)
- **Flexible settings schema** (JSONB for custom configurations)
- **Domain-based tenancy** (primary domain as tenant_id)
- **Automatic validation** (domain format, JSON schema)
- **Audit timestamps** (created_at, updated_at)

## Invitation Service

The InvitationService provides invitation management for team member onboarding, including creation, validation, revocation, and lifecycle management.

### Create Invitation

```go
invitationService := identity.InvitationService()

// Create invitation with roles
maxUses := 1
expiresIn := 7 * 24 * time.Hour // 7 days

invitation, err := invitationService.CreateInvitation(ctx,
    "acme.com",             // Tenant ID
    adminUserID,            // Created by: uuid.UUID of the admin (FK to users.id)
    []string{"Member"},     // Roles (array of role names, validated by app layer)
    "user@acme.com",        // Target email address
    &maxUses,               // Optional max uses (nil = default 1)
    &expiresIn,             // Optional expiration (nil = default 7 days)
)
if err != nil {
    log.Fatal(err)
}

// Send invitation code to user via email/Slack/etc.
fmt.Printf("Invitation Code: %s\n", invitation.Code)
fmt.Printf("Expires: %s\n", invitation.ExpiresAt.Format(time.RFC3339))
```

**Creation Features:**
- Cryptographically secure 20-character code (A-Z, 0-9)
- Multi-role support (array of roles, validated by application layer)
- Default expiration: 7 days
- Default max uses: 1 (single-use invitation)
- Automatic code generation
- Returns created invitation with all metadata

### Get Invitation

```go
// Retrieve invitation by code
invitation, err := invitationService.GetInvitation(ctx, "ABC1234567890XYZQWER")
if err != nil {
    // Invitation not found
    log.Fatal(err)
}

// Access invitation details
fmt.Printf("Tenant: %s\n", invitation.TenantID)
fmt.Printf("Roles: %v\n", invitation.Roles)
fmt.Printf("Uses: %d/%d\n", invitation.CurrentUses, invitation.MaxUses)
fmt.Printf("Expires: %s\n", invitation.ExpiresAt)
```

### Accept Invitation (recommended for signup)

Use `AcceptInvitation` to onboard an invited user. It validates the invitation,
consumes one use, and creates the user **in a single transaction**, so a
single-use invitation can never onboard more than one account (no
validate→create→increment race or over-redemption). The new user's tenant and
roles come from the invitation, and the supplied email must match the
invitation's target.

```go
passwordHash, err := identity.PasswordService().HashPassword(password)
if err != nil {
    return err
}

userID, err := invitationService.AcceptInvitation(ctx, invitationCode, email, displayName, passwordHash)
if err != nil {
    // errors.Is(err, authkit.ErrInvitationInvalid) => unknown, expired, fully used, or email mismatch
    return fmt.Errorf("invitation signup failed: %w", err)
}
// userID is the new user — issue tokens, send a welcome email, etc.
```

Prefer this over composing `ValidateInvitation` + `GetInvitation` + your own user
creation + `IncrementUseCount`: those are lower-level building blocks (below) and
composing them yourself reintroduces a TOCTOU / over-redemption window.

> **Domain policy is not enforced here.** `CreateInvitation` and `AcceptInvitation`
> do **not** check the tenant's `allowed_domains` — by design, since admins
> legitimately invite out-of-domain users (contractors, partners). If you require
> invited emails to stay within the tenant's domain list, call
> `TenantService.ValidateDomainAccess(ctx, email, tenantID)` yourself before
> `CreateInvitation` (see the flow example below).

### Validate Invitation

> **Low-level / read-only.** This only *checks* an invitation; it does not consume
> it. For signup, use `AcceptInvitation` (above) so validation and consumption are
> atomic. Use `ValidateInvitation` for display or pre-flight checks only.

```go
// Read-only check (e.g. to show "invitation valid" in a UI before signup).
// The boolean is the answer; a non-nil error means a genuine system fault, not
// "the invitation is invalid".
valid, err := invitationService.ValidateInvitation(ctx, invitationCode)
if err != nil {
    // Storage/system fault (already sanitized) — surface as a 500.
    return fmt.Errorf("could not validate invitation: %w", err)
}

if !valid {
    // Unknown, expired, or exhausted — a normal "not usable" outcome (false, nil).
    return fmt.Errorf("invitation cannot be used")
}
```

**Validation Checks:**
- Invitation exists
- Not expired (ExpiresAt > NOW())
- Has remaining uses (CurrentUses < MaxUses)
- Unknown/expired/exhausted is reported as `(false, nil)`; `err` is reserved for
  genuine storage faults

### List Invitations

```go
// List all invitations for tenant (including expired)
allInvitations, err := invitationService.ListInvitations(ctx, "acme.com")
if err != nil {
    log.Fatal(err)
}

// List only active invitations (not expired, has uses remaining)
activeInvitations, err := invitationService.ListActiveInvitations(ctx, "acme.com")
if err != nil {
    log.Fatal(err)
}

// Display invitations
for _, inv := range activeInvitations {
    fmt.Printf("Code: %s, Roles: %v, Uses: %d/%d, Expires: %s\n",
        inv.Code, inv.Roles, inv.CurrentUses, inv.MaxUses, inv.ExpiresAt)
}
```

**Listing Features:**
- `ListInvitations`: Returns all invitations (for audit/admin)
- `ListActiveInvitations`: Returns only usable invitations (for UI display)
- Ordered by created_at DESC (newest first)
- Includes usage statistics

### Revoke Invitation

```go
// Soft delete - invalidates invitation but preserves audit trail
err := invitationService.RevokeInvitation(ctx, invitationCode)
if err != nil {
    log.Fatal(err)
}

// Invitation cannot be used, but remains in database
// Sets current_uses = max_uses
```

**Revocation Features:**
- Soft delete (preserves audit trail)
- Sets current_uses = max_uses to prevent use
- Invitation record remains in database
- Logged for security audit

### Delete Invitation

```go
// Permanent deletion from database
err := invitationService.DeleteInvitation(ctx, invitationCode)
if err != nil {
    log.Fatal(err)
}

// Invitation completely removed (hard delete)
```

### Increment Use Count

> **Low-level building block.** The single UPDATE is atomic, but composing
> `ValidateInvitation` → create user → `IncrementUseCount` yourself is **not**
> atomic and can over-redeem a single-use invitation under concurrency. Use
> `AcceptInvitation` for signup; reach for `IncrementUseCount` only for custom
> redemption flows where you manage the surrounding transaction.

```go
err := invitationService.IncrementUseCount(ctx, invitationCode)
if err != nil {
    // Max uses exceeded or invitation not found
    log.Fatal(err)
}

// Atomic increment with database-level constraint (current_uses < max_uses)
```

**Usage Tracking:**
- The increment statement itself is atomic (database constraint enforced)
- Automatic invalidation when max uses reached
- For onboarding, prefer `AcceptInvitation`, which performs validate + increment +
  user creation in one transaction

### Cleanup Expired Invitations

Run periodically (e.g., daily cron job) to maintain database hygiene:

```go
// Delete all expired invitations
count, err := invitationService.CleanupExpiredInvitations(ctx)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Deleted %d expired invitations\n", count)
```

### Complete Invitation Flow Example

```go
// Step 1: Admin creates invitation
func AdminCreateInvitation(ctx context.Context, tenantID string, adminUserID uuid.UUID, inviteeEmail string) (string, error) {
    invitationService := identity.InvitationService()

    // Optional: enforce the tenant's allowed_domains for invited users. The
    // invitation methods do NOT check this themselves; omit this call if you want
    // to allow out-of-domain invitees (contractors, partners).
    if err := identity.TenantService().ValidateDomainAccess(ctx, inviteeEmail, tenantID); err != nil {
        return "", fmt.Errorf("email domain not allowed for tenant: %w", err)
    }

    // Create invitation with defaults (1 use, 7 days expiration)
    invitation, err := invitationService.CreateInvitation(ctx, tenantID, adminUserID, []string{"Member"}, inviteeEmail, nil, nil)
    if err != nil {
        return "", fmt.Errorf("failed to create invitation: %w", err)
    }

    // Send invitation code to invitee via email/Slack
    emailService.SendInvitation(ctx, inviteeEmail, invitation.Code, invitation.ExpiresAt)

    return invitation.Code, nil
}

// Step 2: User signs up with invitation (atomic — recommended)
func UserSignupWithInvitation(ctx context.Context, email, displayName, password, invitationCode string) error {
    invitationService := identity.InvitationService()
    passwordService := identity.PasswordService()

    // Hash the password before creating the user.
    passwordHash, err := passwordService.HashPassword(password)
    if err != nil {
        return fmt.Errorf("password hashing failed: %w", err)
    }

    // AcceptInvitation validates the invitation, consumes one use, and creates the
    // user in a SINGLE transaction. Tenant and roles are taken from the invitation,
    // and the email must match the invitation's target — so a single-use invitation
    // can never onboard more than one account and roles can't be tampered with.
    userID, err := invitationService.AcceptInvitation(ctx, invitationCode, email, displayName, passwordHash)
    if err != nil {
        // errors.Is(err, authkit.ErrInvitationInvalid) => unknown/expired/used/email-mismatch
        return fmt.Errorf("invitation signup failed: %w", err)
    }

    _ = userID // issue tokens, send a welcome email, etc.
    return nil
}

// Step 3: Admin lists active invitations
func AdminListActiveInvitations(ctx context.Context, tenantID string) ([]*model.Invitation, error) {
    invitationService := identity.InvitationService()

    // Get only active invitations for display
    invitations, err := invitationService.ListActiveInvitations(ctx, tenantID)
    if err != nil {
        return nil, fmt.Errorf("failed to list invitations: %w", err)
    }

    return invitations, nil
}

// Step 4: Admin revokes invitation
func AdminRevokeInvitation(ctx context.Context, invitationCode string) error {
    invitationService := identity.InvitationService()

    // Soft delete - preserves audit trail
    err := invitationService.RevokeInvitation(ctx, invitationCode)
    if err != nil {
        return fmt.Errorf("failed to revoke invitation: %w", err)
    }

    return nil
}
```

**Invitation Characteristics:**
- **Cryptographically secure codes** (20 chars, crypto/rand, uppercase + digits)
- **Multi-role support** (array of roles, validated by application layer)
- **Configurable expiration** (default 7 days)
- **Multi-use support** (default single-use, configurable)
- **Atomic redemption** (`AcceptInvitation` validates, consumes, and creates the user in one transaction)
- **Soft delete option** (revoke vs delete for audit trail)
- **Automatic cleanup** (periodic maintenance job)
- **Comprehensive logging** (all operations logged with masked codes)

**Security Considerations:**
- Invitation codes are masked in logs (first 4 chars + ***)
- Role validation is handled by the application layer (library is app-agnostic)
- Expiration enforcement prevents stale invitations
- Usage limits prevent invitation sharing
- `AcceptInvitation` redeems and creates the user in one transaction, preventing
  over-redemption of single-use invitations
- Soft delete preserves audit trail for compliance

## OTP Service (One-Time Password Verification)

The OTPService provides secure OTP generation, validation, and lifecycle management with configurable rate limiting.

### Generate OTP

```go
otpService := identity.OTPService()

// Generate 6-digit OTP with 1-hour expiration.
// Codes are scoped to (tenantID, email, purpose).
response, err := otpService.Generate(ctx, "acme.com", "user@acme.com", "signup", time.Hour)
if err != nil {
    // Rate limit exceeded or generation failed
    log.Fatal(err)
}

// Send OTP via email (use separate email service)
emailService.SendOTP(ctx, email, response.Code, response.ExpiresAt)

// Code: "123456" (6-digit cryptographically secure)
// ExpiresAt: time.Now().Add(time.Hour)
```

**Generation Features:**
- Cryptographically secure 6-digit codes (using `crypto/rand`)
- Configurable expiration duration (e.g., 1 hour for signup, 15 minutes for 2FA)
- Automatic upsert (replaces the existing OTP for the same tenant + email + purpose and resets the attempt counter)
- Rate limiting (default: 1 minute between generation attempts)
- Purpose tracking (`signup`, `reset-password`, `2fa`)

### Validate OTP

```go
// User provides OTP code from email (scoped to tenantID, email, purpose)
err := otpService.Validate(ctx, "acme.com", "user@acme.com", "123456", "signup")
if err != nil {
    // Invalid, expired, not found, or locked out after too many attempts
    return fmt.Errorf("OTP validation failed: %w", err)
}

// OTP is valid and has been deleted (single-use enforcement)
// Proceed with signup/password reset/2FA verification
```

**Validation Features:**
- Tenant-scoped: a code issued in one tenant cannot be verified in another
- Verifies code matches (constant-time comparison)
- Verifies purpose matches (`signup`, `reset-password`, `2fa`, etc.)
- Checks expiration timestamp
- Single-use enforcement (OTP deleted after successful validation)
- Brute-force lockout: after `MaxOTPValidationAttempts` (5) failed guesses the code is invalidated and the caller must request a new one
- Expired OTPs automatically deleted during validation

### Rate Limiting Configuration

```go
identity, err := authkit.New(authkit.Config{
    // ... other config
    OTPConfig: authkit.OTPConfig{
        RateLimitDuration: time.Minute * 2, // 2 minutes between OTP requests
    },
})
```

If a user requests an OTP too soon:
```
Error: "rate limit exceeded: please wait 1m30s before requesting a new OTP"
```

### Complete OTP Flow Example (Signup)

```go
// Step 1: User initiates signup
func InitiateSignup(ctx context.Context, tenantID, email, name string) error {
    otpService := identity.OTPService()

    // Generate OTP with 1-hour expiration (scoped to tenantID + email + purpose)
    response, err := otpService.Generate(ctx, tenantID, email, "signup", time.Hour)
    if err != nil {
        return fmt.Errorf("failed to generate OTP: %w", err)
    }

    // Send OTP via email gateway (separate service)
    err = emailGateway.SendOTP(ctx, email, name, response.Code, response.ExpiresAt)
    if err != nil {
        return fmt.Errorf("failed to send OTP email: %w", err)
    }

    return nil
}

// Step 2: User provides OTP and completes signup
func CompleteSignup(ctx context.Context, tenantID, email, otpCode, password string) error {
    otpService := identity.OTPService()

    // Validate OTP (single-use, auto-deleted on success)
    err := otpService.Validate(ctx, tenantID, email, otpCode, "signup")
    if err != nil {
        return fmt.Errorf("invalid or expired OTP: %w", err)
    }

    // OTP validated successfully - create user account
    passwordService := identity.PasswordService()
    passwordHash, err := passwordService.HashPassword(password)
    if err != nil {
        return fmt.Errorf("password hashing failed: %w", err)
    }

    // Create user in database
    user := createUser(email, passwordHash)
    return userRepo.CreateUser(ctx, user)
}
```

### Delete OTP

```go
// Explicitly revoke OTP (e.g., user cancels operation)
err := otpService.Delete(ctx, "acme.com", "user@acme.com", "signup")
if err != nil {
    log.Fatal(err)
}
```

### Cleanup Expired OTPs

Run periodically (e.g., hourly cron job) to maintain database hygiene:

```go
count, err := otpService.CleanupExpired(ctx)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Deleted %d expired OTPs\n", count)
```

**OTP Characteristics:**
- **One OTP per (tenant, email, purpose) at any time** (upsert behavior)
- **Tenant-scoped** (a code issued in one tenant cannot be read or validated in another)
- **Purpose enforced** (a code generated for one flow cannot validate another)
- **Cryptographically secure generation** (`crypto/rand`, not `math/rand`)
- **6-digit numeric code** (easy to type, SMS-friendly)
- **Configurable expiration** (typical: 1 hour for signup, 15 minutes for 2FA)
- **Generation rate limiting** (prevents spam/abuse)
- **Validation attempt lockout** (after `MaxOTPValidationAttempts` failed guesses the code is invalidated)
- **Single-use enforcement** (deleted after validation)

**Security Considerations:**
- OTP stored in plaintext at rest (needed for validation); validation uses a constant-time comparison
- Generation rate limiting deters spam; **online brute force is bounded by the per-code attempt lockout**, not by the generation rate limit
- Because the code is only 6 digits, prefer a short expiration window and the default attempt lockout; consider a longer code for higher-risk flows
- Short expiration window limits exposure
- Single-use prevents replay attacks
- Purpose tracking for audit trails

## Configuration

### Full Config Example

```go
identity, err := authkit.New(authkit.Config{
    DBConnection: authkit.DatabaseConnection{
        IdentityRWDB:    rwDB,            // Required: write connection
        IdentityRODB:    roDB,            // Required: read connection; can be same as rwDB
        IdentitySchema: "authkit",        // Optional: defaults to "authkit"
    },
    JWTConfig: authkit.JWTConfig{
        AccessSecret:           os.Getenv("JWT_ACCESS_SECRET"),          // Required
        RefreshSecret:          os.Getenv("JWT_REFRESH_SECRET"),         // Required
        RefreshTokenHMACSecret: os.Getenv("REFRESH_TOKEN_HMAC_SECRET"),  // Required
        AccessExpiry:           15 * time.Minute,                        // Optional: defaults to 15 minutes
        RefreshExpiry:          7 * 24 * time.Hour,                      // Optional: defaults to 7 days
    },
    APIKeyConfig: authkit.APIKeyConfig{
        HMACSecret: os.Getenv("API_KEY_HMAC_SECRET"), // Required
    },
    PasswordConfig: authkit.PasswordConfig{
        BcryptCost: 12, // Optional: defaults to 12
    },
    OTPConfig: authkit.OTPConfig{
        RateLimitDuration: time.Minute, // Optional: defaults to 1 minute
    },
    SecretConfig: authkit.SecretConfig{
        EncryptionKey: os.Getenv("SECRET_ENCRYPTION_KEY"), // Optional unless using SecretService
    },
    Logger: logger, // Optional
})
if err != nil {
    return err
}
```

`SecretConfig.EncryptionKey` must be a base64-encoded 32-byte AES-256 key when `SecretService` is used.

### Required Configuration

- **`IdentityRWDB`**: Database connection for write operations (required)
- **`IdentityRODB`**: Database connection for read operations (required)
- **`JWTConfig.AccessSecret`**: Secret for access token signing (required)
- **`JWTConfig.RefreshSecret`**: Secret for refresh token signing (required)
- **`JWTConfig.RefreshTokenHMACSecret`**: Secret for HMAC-SHA256 hashing of refresh tokens in storage (required)
- **`APIKeyConfig.HMACSecret`**: Secret for API key hashing (required)

### Optional Configuration

- **`JWTConfig.AccessExpiry`**: Access token expiration (default: 15 minutes)
- **`JWTConfig.RefreshExpiry`**: Refresh token expiration (default: 7 days)
- **`PasswordConfig.BcryptCost`**: Bcrypt cost factor (default: 12, range: 4-31)
- **`OTPConfig.RateLimitDuration`**: Minimum time between OTP generation attempts (default: 1 minute)
- **`DatabaseConnection.IdentitySchema`**: PostgreSQL schema name (default: `authkit`)
- **`SecretConfig.EncryptionKey`**: Base64-encoded 32-byte AES-256 key for `SecretService`
- **`Logger`**: Logger implementation (default: nil, no logging)

### Expiration Duration

`CreateAPIKeyRequest.ExpiresIn` is a `*time.Duration` (nil means the key never
expires). The key expires at `time.Now().Add(*ExpiresIn)`. Express longer spans as
plain durations:

- `30 * 24 * time.Hour` - 30 days
- `6 * 30 * 24 * time.Hour` - ~6 months (30 days per month)
- `365 * 24 * time.Hour` - ~1 year

## Database Schema

The library currently requires PostgreSQL with the `authkit` schema containing the following tables:

- **`authkit.tenants`**: Organization definitions with allowed email domains
- **`authkit.users`**: User profiles with tenant association and roles
- **`authkit.invitations`**: Access codes for member/viewer signup
- **`authkit.api_keys`**: Tenant-scoped API keys (HMAC-SHA256 hashed)
- **`authkit.refresh_tokens`**: Refresh token session records (HMAC-SHA256 hashed)
- **`authkit.verification_codes`**: OTP codes for email verification
- **`authkit.provider_keys`**: Encrypted provider secrets

Migration scripts are included in [`migrations/`](migrations/):

```bash
migrate -path migrations -database "$DATABASE_URL" up
```

### Configurable Schema

By default, the repository queries `authkit.*`. You can configure a different PostgreSQL schema with `DatabaseConnection.IdentitySchema`:

```go
identity, err := authkit.New(authkit.Config{
    DBConnection: authkit.DatabaseConnection{
        IdentityRWDB:    rwDB,
        IdentityRODB:    roDB,
        IdentitySchema: "my_identity",
    },
    // ...
})
```

Schema names are validated as simple PostgreSQL identifiers and quoted before being inserted into SQL. If you use a custom schema, copy the migration and replace `authkit` with your schema name before applying it.

## Security Best Practices

### API Key Storage

- **Never store plaintext API keys** - Only HMAC-SHA256 hashes are stored
- **Return plaintext key only once** - During creation, after that it's never retrievable
- **Use HTTPS** - Always transmit API keys over encrypted connections
- **Rotate keys regularly** - Implement key rotation policies

### HMAC Secret Management

```go
// ❌ Don't hardcode secrets
APIKeyConfig: authkit.APIKeyConfig{
    HMACSecret: "my-secret-key",
}

// ✅ Load from environment or secret manager
APIKeyConfig: authkit.APIKeyConfig{
    HMACSecret: os.Getenv("API_KEY_HMAC_SECRET"),
}
```

### UUID v7

The library uses UUID v7 for all identifiers:

- Time-ordered for better database indexing
- Chronologically sortable
- Cryptographically secure

```go
import "github.com/google/uuid"

// Used internally for all IDs
keyID, err := uuid.NewV7()
```

## Architecture

### Layered Design

```
authkit-go/
├── model/                    # Data models, request/response structs, sentinel errors (public)
├── logger/                   # Logger interface + NopLogger (public)
├── internal/
│   ├── repository/           # Database operations (CRUD) — not importable by consumers
│   └── service/              # Business logic layer — not importable by consumers
├── config.go                 # Configuration structures (public)
└── main.go                   # Library entry point: New + AuthKit accessors (public)
```

Only the root `authkit` package, `model`, and `logger` are part of the public
import surface; `service` and `repository` live under `internal/` and are reached
exclusively through `AuthKit`'s accessor methods (`AuthService()`, etc.).

### Service Layer Pattern

All business logic is encapsulated in service layer:

```go
// Get service instances from AuthKit
apiKeyService := identity.APIKeyService()
passwordService := identity.PasswordService()
jwtService := identity.JWTService()
tokenService := identity.TokenService()
authService := identity.AuthService()
otpService := identity.OTPService()
tenantService := identity.TenantService()
invitationService := identity.InvitationService()
```

### Read-Write Connection Separation

The library optimizes database access by separating read and write operations:

- **Write operations** (`CreateAPIKey`, `RevokeAPIKey`) use `IdentityRWDB`
- **Security-sensitive validation** (`ValidateAPIKey`, refresh token validation/rotation) uses `IdentityRWDB` to avoid replica-lag acceptance after revocation
- **Non-critical reads** (`ListAPIKeys`, tenant/user list operations) use `IdentityRODB`
- Supports PostgreSQL read replicas for horizontal scaling

## Error Handling

Service methods return **sentinel errors** (`authkit.Err*`), wrapped with `%w`
for context, so branch on them with `errors.Is` rather than matching error
strings. Map them to status codes — and treat anything you don't recognize
(including `authkit.ErrInternal`) as a 500, **not** a 401:

```go
claims, err := authService.ValidateJWT(ctx, token)
switch {
case err == nil:
    // authorized — use claims
case errors.Is(err, authkit.ErrInvalidToken), errors.Is(err, authkit.ErrTokenRevoked):
    http.Error(w, "unauthorized", http.StatusUnauthorized) // 401
case errors.Is(err, authkit.ErrAccountDisabled), errors.Is(err, authkit.ErrAccountLocked):
    http.Error(w, "forbidden", http.StatusForbidden) // 403
default:
    // ErrInternal or any unexpected fault: log server-side, do NOT leak err to the client
    log.Error("jwt validation failed", zap.Error(err))
    http.Error(w, "internal error", http.StatusInternalServerError) // 500
}
```

Exported sentinels include `ErrInvalidCredentials`, `ErrAccountDisabled`,
`ErrAccountLocked`, `ErrInvalidToken`, `ErrTokenRevoked`, `ErrInvalidRefreshToken`,
`ErrRefreshTokenReuse`, `ErrInvalidOTP`, `ErrOTPLockedOut`, `ErrOTPRateLimited`,
`ErrInvalidAPIKey`, `ErrIncorrectPassword`, `ErrInvitationInvalid`, `ErrUserExists`,
`ErrPasswordTooWeak`, `ErrSecretEncryptionKeyMissing`, `ErrNotFound`, and
`ErrInternal`. `ErrPasswordTooWeak` covers strength failures (too short, too long,
or a missing character class) from `ChangePassword`/`ValidatePasswordStrength`/
`HashPassword`; `ErrSecretEncryptionKeyMissing` is returned by `SecretService`
operations when no valid encryption key was configured. `Login` deliberately
collapses not-found / wrong-password / disabled / locked into a single
`ErrInvalidCredentials` to avoid account enumeration; the specific reason is
logged server-side only.

**Do not render `err.Error()` to end users** — wrapped errors may carry internal
context. Map to a status with `errors.Is`, and log the raw error server-side.

## Performance Considerations

### Async Last Used Tracking

API key validation updates `last_used_at` asynchronously to avoid blocking:

```go
// ValidateAPIKey returns immediately
context, err := apiKeyService.ValidateAPIKey(ctx, apiKey)
// last_used_at updated in background goroutine
```

### Database Connection Pooling

Configure connection pools for optimal performance:

```go
rwDB.SetMaxOpenConns(25)
rwDB.SetMaxIdleConns(5)
rwDB.SetConnMaxLifetime(time.Minute * 5)

roDB.SetMaxOpenConns(50)  // More read connections
roDB.SetMaxIdleConns(10)
roDB.SetConnMaxLifetime(time.Minute * 5)
```

## Testing

### Unit Tests

```bash
make test
```

### Integration Tests

Integration tests use Docker Compose to run PostgreSQL, apply the migrations, and exercise repository paths against a real schema.

```bash
make postgres-up
make test-integration
make postgres-down
```

The default integration database URL is:

```text
postgres://authkit_test:authkit_test@localhost:55432/authkit_test?sslmode=disable
```

Override it with `IDENTITY_TEST_DATABASE_URL` if needed.

To reset the database volume and re-run migrations from scratch:

```bash
make postgres-reset
make test-integration
```

## Examples

Complete working examples are planned. Useful first examples would include:

- `api_key_management.go` - API key CRUD operations
- `custom_logger.go` - Integrating with zap/logrus
- `multi_tenant.go` - Multi-tenant user management

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for development and pull request guidance.

### Development Setup

1. Clone the repository:
```bash
git clone https://github.com/modgudinc/authkit-go.git
cd authkit-go
```

2. Install dependencies:
```bash
go mod download
```

3. Run tests:
```bash
make test
```

4. Run integration tests:
```bash
make postgres-up
make test-integration
```

5. Run linter:
```bash
make lint
```

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/modgudinc/authkit-go/issues)
- **Documentation**: [docs/](docs/)
- **Security**: [SECURITY.md](SECURITY.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

## Roadmap

- [x] API Key Management
- [x] Password Hashing Service (bcrypt)
- [x] JWT Service (token generation & validation)
- [x] Token Service (combined JWT + refresh token management)
- [x] Auth Service (login, logout, token refresh, JWT validation)
- [x] OTP Service (one-time password generation & validation with rate limiting)
- [x] Tenant Service (tenant management, settings, domain validation)
- [x] Invitation Service (invitation management, validation, revocation)
- [ ] Audit Logging (planned)
- [ ] Rate Limiting (planned)
- [ ] Key Rotation Support (planned)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.
