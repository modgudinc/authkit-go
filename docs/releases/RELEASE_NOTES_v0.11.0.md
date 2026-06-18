# authkit-go v0.11.0

A breaking API-ergonomics cleanup bundled with the security, correctness, and
hardening work accumulated since v0.10.0. Most service methods are renamed to bare,
namespaced verbs. **No schema migration is required** to upgrade (the `000001`
migration was corrected in place — see below — but a deployed schema keeps working).

```bash
go get github.com/modgudinc/authkit-go@v0.11.0
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## Why this release

v0.10.0 already removed `TokenService.RevokeAllUserTokens` from the public interface
(a cross-tenant footgun), which is itself a breaking change. Rather than ship that as
a misleading patch, this release also lands the deferred ergonomics cleanup: each
service namespaces its noun (`APIKeyService`, `TenantService`, …), so the redundant
type suffix on every method (`CreateAPIKey`, `GetTenant`, `SaveSecret`, …) was just
noise. Methods are now bare verbs (`Create`, `Get`, `Save`, …), duplicate
`UserService` methods are gone, and the `Update` call style is consistent with the
rest of the create/update family.

## Breaking changes

### Method renames (drop the redundant type suffix)

| Service | Before | After |
|---------|--------|-------|
| **APIKeyService** | `CreateAPIKey` / `ValidateAPIKey` / `ListAPIKeys` / `GetAPIKey` / `RevokeAPIKey` / `CountByTenant` / `CleanupExpiredKeys` | `Create` / `Validate` / `List` / `Get` / `Revoke` / `Count` / `CleanupExpired` |
| **TenantService** | `CreateTenant` / `GetTenant` / `GetTenantByDomain` / `ListTenants` / `TenantExists` | `Create` / `Get` / `GetByDomain` / `List` / `Exists` |
| **InvitationService** | `CreateInvitation` / `GetInvitation` / `ListInvitations` / `ListActiveInvitations` / `ValidateInvitation` / `AcceptInvitation` / `RevokeInvitation` / `DeleteInvitation` / `CleanupExpiredInvitations` | `Create` / `Get` / `List` / `ListActive` / `Validate` / `Accept` / `Revoke` / `Delete` / `CleanupExpired` |
| **SecretService** | `SaveSecret` / `GetSecret` / `ListSecrets` / `DeleteSecret` / `CountByTenant` | `Save` / `Get` / `List` / `Delete` / `Count` |
| **TokenService** | `CleanupExpiredTokens` | `CleanupExpired` |
| **UserService** | `EnableByTenant` / `DisableByTenant` / `CountByTenant` / `UpdateRolesByTenant` | `Enable` / `Disable` / `Count` / `UpdateRoles` |

`InvitationService.IncrementUseCount`/`HasPending`, `SecretService.MarkVerified`,
`TenantService.UpdateName`/`UpdateSettings`/`SetAllowedDomains`/`AddAllowedDomain`/`ValidateDomainAccess`,
and all of `AuthService`/`JWTService`/`PasswordService`/`OTPService` are unchanged.

### `UserService` — removed duplicates and a signature change

- The duplicate `Enable`/`Disable` aliases are removed; `EnableByTenant`/`DisableByTenant`
  are now simply `Enable`/`Disable` (every `UserService` mutator is already tenant-scoped,
  so the suffix signalled nothing).
- `UserService.Update` now takes the ids inside the request struct, matching `Create`
  and `AuthService.ChangePassword`:

  ```go
  // Before
  err := userService.Update(ctx, userID, tenantID, model.UpdateUserRequest{DisplayName: &name})
  // After
  err := userService.Update(ctx, model.UpdateUserRequest{
      UserID: userID, TenantID: tenantID, DisplayName: &name,
  })
  ```

### Convention going forward

Create/update operations take a keyed request struct with the identity inside
(`Create`, `Update`, `ChangePassword`); simple get/delete/status/role operations take
positional ids (`userID, tenantID`). Every mutator is tenant-scoped.

## Security & correctness (since v0.10.0)

- **JWT revocation & login gates now read the primary, not a replica.** `ValidateJWT`
  (the `token_version`/`is_enabled`/`is_locked` gate) and `Login`'s status gate read
  from the primary, so `LogoutAll`/`ChangePassword`/disable/lock take effect immediately
  instead of after replication lag (a fail-open window). Deployments using one `*sql.DB`
  for both handles were never affected.
- **Single-session logout now soft-revokes** the refresh token (retains the row) so a
  replay trips `ErrRefreshTokenReuse` family revocation, matching rotation's guarantee.
- **`ChangePassword` updates the password and bumps `token_version` atomically** (one
  tenant-scoped UPDATE) so it can never be left half-applied.
- **An OTP attempt-lockout no longer resets the generation rate-limit** (the locked-out
  row is retained as a cooldown tombstone), preventing OTP-email spam amplification.
- **`CreateAPIKey` (now `Create`) no longer leaks raw driver errors**; over-length
  inputs surface as the new matchable `ErrValueTooLong` sentinel instead of `ErrInternal`.
- **`OTPService.Generate` rejects a non-positive `ExpirationDuration`** (previously minted
  an already-expired, unusable code); **`InvitationService.Create` validates the target
  email and bounds `MaxUses`.**
- **`DummyVerify` no longer latches a generation failure** (login timing equalizer can't
  be silently disabled).

## Schema / CI

- `allowed_domains` non-empty CHECK now uses `cardinality(...) > 0` (the old
  `array_length(...) > 0` was `NULL` for `'{}'` and didn't reject it). Two redundant
  indexes were dropped. Both edits are in the consolidated `000001` migration; a fresh
  `migrate up` gets the corrected schema, existing deployments are unaffected.
- Added `.github/dependabot.yml`; hardened the gosec CI step (explicit thresholds +
  SARIF artifact).

## Documentation

Caller-owned rate limiting, the AES-GCM single-key assumption, JWT-claim PII, the
full-record requirement for `GenerateAccessToken`/`GenerateTokenPair`, and secret
generation (`openssl rand -base64 32`) are now documented in SECURITY.md / README /
godoc. README and the `docs/` examples use the new method names.

## Upgrading

1. Apply the method renames in the table above (each is a pure rename — same args,
   same behavior). `model.*Request`/`*Response` type names are unchanged.
2. Move `userID, tenantID` into `model.UpdateUserRequest` for `UserService.Update`.
3. Replace `EnableByTenant`/`DisableByTenant`/`CountByTenant`/`UpdateRolesByTenant`
   with `Enable`/`Disable`/`Count`/`UpdateRoles` (and drop any reliance on the old
   `Enable`/`Disable` aliases — same behavior, same name now).
4. If you called `TokenService.RevokeAllUserTokens` directly (removed in v0.10.0), use
   `AuthService.LogoutAll(ctx, userID, tenantID)`.

## Verification

`gofmt`, `go vet` (default + `integration`), and `golangci-lint` (default config) are
clean; the unit suite and the PostgreSQL integration suite (rotation, refresh-token
reuse, cross-tenant isolation, OTP lockout) pass.

---

Full changes: see [CHANGELOG.md](../../CHANGELOG.md). Licensed under [Apache-2.0](../../LICENSE).
