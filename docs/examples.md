# Service Examples

These examples show typical service usage. They assume `identity` is an initialized `authkit.AuthKit` value and `ctx` is a request context.

A user is a **global identity** (no tenant, no roles); tenant access is a **membership**. So the usual onboarding order is: create a tenant, create the global user, then grant the user a membership in that tenant. A login mints a **workspace-scoped** access token for one active membership.

## Tenants

```go
tenantService := identity.TenantService()

tenant, err := tenantService.Create(ctx, model.CreateTenantRequest{
	TenantID:       "acme.com",
	Name:           "Acme",
	AllowedDomains: []string{"acme.com"},
})
if err != nil {
	return err
}

if err := tenantService.ValidateDomainAccess(ctx, "admin@acme.com", tenant.TenantID); err != nil {
	return err
}
```

## Users And Memberships

A `UserService.Create` makes a **global** identity (globally-unique email, no tenant/roles). Grant tenant access separately with `MembershipService.Add` — the roles are opaque strings your application interprets.

```go
passwordService := identity.PasswordService()
userService := identity.UserService()
membershipService := identity.MembershipService()

hash, err := passwordService.HashPassword("ValidPass1!")
if err != nil {
	return err
}

// Global identity — no tenant, no roles.
userID, err := userService.Create(ctx, model.CreateUserRequest{
	Email:        "admin@acme.com",
	PasswordHash: hash,
	DisplayName:  "Admin",
})
if err != nil {
	return err
}

// Grant the identity an active membership in the tenant (with app-defined roles).
if err := membershipService.Add(ctx, model.AddMembershipRequest{
	UserID:   userID,
	TenantID: "acme.com",
	Roles:    []string{"Admin"},
}); err != nil {
	return err
}

// A user's workspaces / a tenant's members:
workspaces, err := membershipService.ListByUser(ctx, userID)   // []*model.Membership
if err != nil {
	return err
}
members, err := membershipService.ListByTenant(ctx, "acme.com") // []*model.Membership
if err != nil {
	return err
}
_, _ = workspaces, members

// Change roles (bumps the membership token_version -> that workspace's access tokens
// must refresh to pick up the new roles); revoke (soft-revoke: suspends the membership).
if err := membershipService.UpdateRoles(ctx, userID, "acme.com", []string{"Operator"}); err != nil {
	return err
}
// if err := membershipService.Remove(ctx, userID, "acme.com"); err != nil { return err }
```

## Account Status And Audit Trail

Account status is **identity-level** (a user is global), keyed by the user id.

```go
userService := identity.UserService()

// Status controls (identity-level; Disable/Lock also revoke the identity's sessions).
if err := userService.Disable(ctx, userID); err != nil {
	return err
}
if err := userService.Enable(ctx, userID); err != nil {
	return err
}

// Read the enable/disable/lock/unlock audit trail (newest first).
history, err := userService.StatusHistory(ctx, userID)
if err != nil {
	return err
}
_ = history // []*model.UserStatusChange

// The audit table has no expiry — prune it on a schedule (olderThan must be positive).
removed, err := userService.CleanupStatusChanges(ctx, 90*24*time.Hour)
if err != nil {
	return err
}
_ = removed
```

## Rate Limiting And Health Checks

`RateLimiter`, `Metrics`, and health checks are wired at construction; see
[patterns.md](patterns.md) for a `Config.RateLimiter` implementation (rejections
surface as `authkit.ErrRateLimited` / 429) and a readiness probe using
`identity.Ping(ctx)` (with `Config.VerifyConnectivity` for fail-fast startup).

## Login And JWT Validation

`Login` authenticates into a **known** workspace and returns a workspace-scoped access
token (plus an identity-session refresh token). The user must have an **active
membership** in `TenantID`, otherwise `Login` returns `authkit.ErrNoActiveMembership`.

```go
authService := identity.AuthService()

login, err := authService.Login(ctx, model.LoginRequest{
	Email:    "admin@acme.com",
	Password: "ValidPass1!",
	TenantID: "acme.com",
	SessionInfo: &model.SessionInfo{
		IPAddress:  "203.0.113.10",
		UserAgent:  "example-client",
		DeviceName: "laptop",
	},
})
if err != nil {
	return err // errors.Is(err, authkit.ErrNoActiveMembership) -> 403; ErrInvalidCredentials -> 401
}

// login.AccessToken is scoped to login.TenantID; login.Memberships lists the user's workspaces.
claims, err := authService.ValidateJWT(ctx, login.AccessToken)
if err != nil {
	return err
}
_ = claims // claims.TenantID, claims.Roles come from the active membership
```

## Login Without A Known Workspace (and switching workspace)

When the workspace is not known up front, `LoginByEmail` authenticates the identity and
opens the session. It mints a token immediately when `TenantID` is given or the identity
has exactly one active membership; otherwise it returns the memberships to choose from
(no access token yet). Use `MintWorkspaceToken` to select/switch a workspace from the
same session — no re-login, the refresh token is unchanged.

```go
authService := identity.AuthService()

byEmail, err := authService.LoginByEmail(ctx, model.LoginByEmailRequest{
	Email:    "admin@acme.com",
	Password: "ValidPass1!",
})
if err != nil {
	return err
}

// byEmail.Memberships is always populated. If exactly one active membership (or you
// passed TenantID), byEmail.AccessToken is already set. Otherwise the caller picks a
// workspace and mints a token for it from the identity session:
if byEmail.AccessToken == "" && len(byEmail.Memberships) > 0 {
	ws, err := authService.MintWorkspaceToken(ctx, byEmail.RefreshToken, byEmail.Memberships[0].TenantID)
	if err != nil {
		return err
	}
	_ = ws // ws.AccessToken scoped to ws.TenantID
}
```

## Refresh And Logout

`RefreshToken` rotates the identity-session refresh token and re-mints a workspace-scoped
access token, so it carries the target `TenantID`. `LogoutAll` is identity-level (it
invalidates every workspace's access tokens and revokes all refresh tokens).

```go
refreshed, err := authService.RefreshToken(ctx, model.RefreshRequest{
	RefreshToken: login.RefreshToken,
	TenantID:     "acme.com",
})
if err != nil {
	return err
}

// Single-session logout:
if err := authService.Logout(ctx, refreshed.RefreshToken); err != nil {
	return err
}

// Or log out of every workspace and device for the identity:
if err := authService.LogoutAll(ctx, userID); err != nil {
	return err
}
```

## API Keys

```go
apiKeyService := identity.APIKeyService()
expiresIn := 90 * 24 * time.Hour

created, err := apiKeyService.Create(ctx, model.CreateAPIKeyRequest{
	TenantID:  "acme.com",
	CreatedBy: userID, // a global user id
	Name:      "Production",
	ExpiresIn: &expiresIn,
})
if err != nil {
	return err
}

// Store or display created.APIKey once. It is never stored in plaintext.
keyContext, err := apiKeyService.Validate(ctx, created.APIKey)
if err != nil {
	return err
}

_ = keyContext
```

## Invitations

`Accept` redeems the invitation atomically and resolves the invitee's **global**
identity: it reuses the existing identity for the email (so an invited user does not get
a second account/password) or creates one, then grants the invited membership. It returns
the user id and whether a new identity was created.

```go
invitationService := identity.InvitationService()

invitation, err := invitationService.Create(ctx, model.CreateInvitationRequest{
	TenantID:  "acme.com",
	CreatedBy: userID,
	Email:     "invitee@acme.com",
	Roles:     []string{"Member"},
})
if err != nil {
	return err
}

// Redeem: validate + consume one use + reuse-or-create the identity + grant the
// membership, all in one transaction. Prefer this over Validate + IncrementUseCount,
// which is non-atomic and can over-redeem a single-use invitation.
passwordHash, err := identity.PasswordService().HashPassword("SecurePass1!")
if err != nil {
	return err
}
invitedUserID, created, err := invitationService.Accept(ctx, model.AcceptInvitationRequest{
	Code:         invitation.Code,
	Email:        "invitee@acme.com",
	DisplayName:  "Invited User",
	PasswordHash: passwordHash, // used only when creating a NEW identity
})
if err != nil {
	return err
}
_, _ = invitedUserID, created // created == false means an existing identity was reused
```

## OTP

OTPs are keyed by `(email, purpose)` globally (email is a global identity, so an OTP is
identity-level, not tenant-scoped).

```go
otpService := identity.OTPService()

generated, err := otpService.Generate(ctx, model.OTPGenerateRequest{
	Email:              "user@acme.com",
	Purpose:            "signup",
	ExpirationDuration: time.Hour,
})
if err != nil {
	return err
}

// Send generated.Code through your email/SMS provider.
if err := otpService.Validate(ctx, model.OTPValidateRequest{
	Email:   "user@acme.com",
	Code:    generated.Code,
	Purpose: "signup",
}); err != nil {
	return err
}
```

## Secrets

```go
secretService := identity.SecretService()

saved, err := secretService.Save(ctx, model.SaveSecretRequest{
	TenantID:   "acme.com",
	Key:        "openai",
	PlainValue: "sk-live-secret", // placeholder — pass the real provider key here
	CreatedBy:  userID,
})
if err != nil {
	return err
}

plain, err := secretService.Get(ctx, saved.TenantID, saved.Key)
if err != nil {
	return err
}

_ = plain
```
