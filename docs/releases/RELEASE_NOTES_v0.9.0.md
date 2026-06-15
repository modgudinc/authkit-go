# authkit-go v0.9.0

The API-ergonomics release: it clears the breaking findings from the full review —
a dead required secret, a stringly-typed settings field, a seven-argument
constructor, an all-or-nothing update, and internal types leaking into the public
package. No schema migration is required.

```bash
go get github.com/modgudinc/authkit-go@v0.9.0
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## Breaking changes

| Change | Before | After |
|--------|--------|-------|
| `JWTConfig.RefreshSecret` removed | required, but unused | delete it; refresh tokens use `RefreshTokenHMACSecret` |
| `CreateInvitation` signature | 7 positional params | `CreateInvitation(ctx, model.CreateInvitationRequest{…})` |
| `UpdateUserRequest` fields | `DisplayName string`, `Roles []string` | `*string`, `*[]string` (nil = leave unchanged) |
| `Tenant.Settings` | `string` (raw JSON) | `map[string]any` |

### `JWTConfig.RefreshSecret` removed

It was validated as a required ≥32-byte secret but never used — refresh tokens are
opaque random strings hashed with `RefreshTokenHMACSecret`, not signed. Drop the
field from your `JWTConfig`; nothing else changes.

### `CreateInvitation` takes a request struct

```go
inv, err := identity.InvitationService().CreateInvitation(ctx, model.CreateInvitationRequest{
    TenantID:  "acme.com",
    CreatedBy: adminUserID,
    Email:     "user@acme.com",
    Roles:     []string{"Member"},
    // MaxUses *int and ExpiresIn *time.Duration are optional (default 1 use / 7 days)
})
```

### `UpdateUserRequest` supports partial updates

Each field is now a pointer; a nil field leaves that column untouched. And
`token_version` is bumped **only when roles change**, so a display-name-only edit no
longer logs the user out of all sessions.

```go
name := "New Name"
// update only the display name; roles and sessions are left alone
identity.UserService().Update(ctx, userID, tenantID, model.UpdateUserRequest{DisplayName: &name})
```

### `Tenant.Settings` is a map

Read and write the same `map[string]any`, so a round-trip needs no manual JSON:

```go
t, _ := identity.TenantService().GetTenant(ctx, tenantID)
t.Settings["theme"] = "dark"
identity.TenantService().UpdateSettings(ctx, tenantID, t.Settings)
```

## Internal (not part of the public API)

- The repository plumbing types `VerificationCode`, `CreateVerificationCodeRequest`,
  `OTPConsumeResult`, `RefreshToken`, and `CreateRefreshTokenRequest` moved from the
  public `model` package into `internal/repository` — they were never consumer-facing.
  `model.GenerateResponse` and `model.SessionInfo` remain public.
- Removed the dead non-tenant repository mutators (the tenant-scoped variants were
  always the live path).

## Upgrading

1. Delete `RefreshSecret` from your `JWTConfig`.
2. Switch `CreateInvitation` calls to the `model.CreateInvitationRequest` form.
3. Wrap `UpdateUserRequest` field values in pointers (`&name`, `&roles`).
4. Treat `Tenant.Settings` as a `map[string]any` instead of a JSON string.

## Verification

`gofmt`, `go vet` (default + `integration`), and `golangci-lint` are clean; unit and
PostgreSQL integration tests pass, including new coverage for partial user updates
(display-name-only leaves roles and `token_version` untouched; a roles change bumps
`token_version`).

---

Full changes: see [CHANGELOG.md](../../CHANGELOG.md). Licensed under [Apache-2.0](../../LICENSE).
