# authkit-go v0.10.0

A security release that closes a tenant-isolation gap in the per-user methods,
bundled with an API-ergonomics cleanup. Several public signatures change. No schema
migration is required.

```bash
go get github.com/modgudinc/authkit-go@v0.10.0
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## Why this release

The library consistently provides tenant-scoped `*ByTenant` methods and uses them
almost everywhere. But a cluster of per-user methods accepted a bare user id and
reached repository queries that filtered on `id` only — bypassing the tenant check
the rest of the API enforces. A caller acting for tenant B, holding another tenant's
user UUID, could:

- read that user's bcrypt password hash (`UserService.VerifyPassword`),
- drive it toward account lockout (`IncrementFailedLoginCount`) — a cross-tenant DoS,
- overwrite its `last_login` (`UpdateLastLogin`),
- force-log-it-out of all sessions (`AuthService.LogoutAll`), and
- with the old password, change its password (`AuthService.ChangePassword`).

`UserService.GetByIDOnly` was an even more direct hazard: it returned a full user
record — including the password hash — by id alone.

The fix is to require and enforce a tenant on every one of these paths.

## Breaking changes

| Method | Before | After |
|--------|--------|-------|
| `AuthService.LogoutAll` | `(ctx, userID)` | `(ctx, userID, tenantID)` |
| `AuthService.ChangePassword` | `ChangePasswordRequest{UserID, …}` | `ChangePasswordRequest{UserID, TenantID, …}` (TenantID required) |
| `UserService.VerifyPassword` | `(ctx, userID)` | `(ctx, userID, tenantID)` |
| `UserService.UpdateLastLogin` | `(ctx, userID)` | `(ctx, userID, tenantID)` |
| `UserService.IncrementFailedLoginCount` | `(ctx, userID)` | `(ctx, userID, tenantID)` |
| `UserService.GetDisplayName` | `(ctx, userID)` | `(ctx, userID, tenantID)` |
| `UserService.GetByIDOnly` | present | **removed** (use `GetByID(ctx, userID, tenantID)`) |
| `InvitationService.AcceptInvitation` | 4 positional strings | `model.AcceptInvitationRequest{…}` |
| `OTPService.Generate` | 4 positional args | `model.OTPGenerateRequest{…}` |
| `OTPService.Validate` | 4 positional strings | `model.OTPValidateRequest{…}` |

### Tenant-scoped self-service auth

```go
// LogoutAll now fails closed if userID does not belong to tenantID.
err := authService.LogoutAll(ctx, userID, tenantID)

err := authService.ChangePassword(ctx, model.ChangePasswordRequest{
    UserID:      userID,
    TenantID:    tenantID, // required
    OldPassword: oldPassword,
    NewPassword: newPassword,
})
```

`LogoutAll` increments `token_version` scoped to the tenant *first*: a cross-tenant
id matches no row and returns `ErrNotFound` before any refresh token is touched.

### Request structs for invitations and OTP

```go
userID, err := invitationService.AcceptInvitation(ctx, model.AcceptInvitationRequest{
    Code:         code,
    Email:        email,
    DisplayName:  displayName,
    PasswordHash: passwordHash,
})

resp, err := otpService.Generate(ctx, model.OTPGenerateRequest{
    TenantID: "acme.com", Email: "user@acme.com", Purpose: "signup", ExpirationDuration: time.Hour,
})
err = otpService.Validate(ctx, model.OTPValidateRequest{
    TenantID: "acme.com", Email: "user@acme.com", Code: resp.Code, Purpose: "signup",
})
```

## Internal (not part of the public API)

- The tenant-less repository mutators (`SetPassword`, `VerifyPassword`,
  `IncrementTokenVersion`, `IncrementFailedLoginCount`, `UpdateLastLogin`, `Unlock`,
  `GetDisplayName`) were removed in favor of their `*ByTenant` variants, so the
  unscoped query can no longer be reintroduced by accident. Internal call sites that
  already held a tenant (login auto-unlock, JWT-validation auto-unlock, last-login)
  now route through the scoped variants.

## Upgrading

1. Add `tenantID` to `LogoutAll`, `VerifyPassword`, `UpdateLastLogin`,
   `IncrementFailedLoginCount`, and `GetDisplayName` calls.
2. Set `TenantID` on `ChangePasswordRequest`.
3. Replace `GetByIDOnly(ctx, userID)` with `GetByID(ctx, userID, tenantID)`.
4. Switch `AcceptInvitation`, `OTPService.Generate`, and `OTPService.Validate` to
   their request-struct forms.

## Verification

`gofmt`, `go vet` (default + `integration`), and `golangci-lint` are clean; unit and
PostgreSQL integration tests pass. A new integration test,
`TestCrossTenantUserOperationsAreRejected`, drives every scoped method cross-tenant
and asserts `ErrNotFound` with no side effect on the victim account, alongside
same-tenant positive controls.

---

Full changes: see [CHANGELOG.md](../../CHANGELOG.md). Licensed under [Apache-2.0](../../LICENSE).
