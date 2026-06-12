# authkit-go v0.3.0

An API-surface and consistency release that closes the remaining low/info items
from the OSS-readiness review. It contains **breaking changes** (acceptable
pre-1.0) and **a new database migration** — read "Upgrading" before bumping.

```bash
go get github.com/modgudinc/authkit-go@v0.3.0
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## Highlights

- **Tighter public surface.** The `service` and `repository` packages moved under
  `internal/` — consumers use `AuthKit`'s accessor methods exclusively. The
  repository-only `model.InsertAPIKeyParams` DTO was removed from the public
  `model` package.
- **Correct types.** `CreatedBy` is now `uuid.UUID` everywhere (it is a FK to
  `users.id`), and `api_keys.key_id` is a `UUID` column. Id columns now default to
  a time-ordered `uuid_generate_v7()` so DB-default and trigger-populated rows are
  v7, not v4.
- **Safer logging.** The `Logger` interface gains a `Debug` level, and the library
  now defaults to a no-op logger so a missing nil-guard can never panic.
- **Race-free lockout.** The failed-login lockout decision is made atomically in
  the database.
- **No driver leaks.** Read/list/get methods return a generic `ErrInternal` for
  genuine DB faults instead of the wrapped driver error (sentinels still pass
  through for `errors.Is`).

## Breaking changes

| Change | Migration |
|--------|-----------|
| `service` / `repository` moved to `internal/` | Use `AuthKit` accessors (`AuthService()`, `UserService()`, …) |
| `New` returns `*AuthKit` (was `AuthKit`) | `kit, err := authkit.New(...)` unchanged; `var kit authkit.AuthKit` → `*authkit.AuthKit` |
| `Logger` requires a `Debug` method | Add `Debug(msg string, fields ...interface{})` to your implementation |
| `CreatedBy` is `uuid.UUID` (models + request structs); `CreateInvitation` `createdBy` is `uuid.UUID` | Pass `userID` instead of `userID.String()` |
| `model.InsertAPIKeyParams` removed | Use `APIKeyService.CreateAPIKey` with `model.CreateAPIKeyRequest` |

## New

- `authkit.ErrInternal` sentinel for generalized internal failures.
- `jti` (unique token id) on access tokens — `claims.ID`.
- `logger.Logger.Debug` level; nil `Config.Logger` defaults to `logger.NopLogger`.
- Migration `000002_uuid_consistency` (`api_keys.key_id` → `UUID`; v7 id defaults).

## Security

- **`ChangePassword`** no longer reports success when post-update session
  revocation fails — it returns an error so callers can force a re-login instead
  of leaving old tokens valid.
- **OTP generation rate limiting** now reads from the primary (not a replica, so
  replication lag can't hide a just-issued code) and no longer fails open on a
  transient read error.
- **Emails are masked in logs** (`u***@acme.com`) and the login "user not found"
  path no longer logs the raw lookup error (account-enumeration hardening).
- **Failed-login lockout** is now an atomic `UPDATE ... RETURNING`, so concurrent
  failures cannot trip the lock one attempt early or late.
- The OTP rate-limit read no longer selects the plaintext code back from the DB.

## Error contract & correctness

- `JWTService.ValidateAccessToken` wraps `ErrInvalidToken` on all paths;
  duplicate `(tenant, email)` creation/invitation returns `ErrUserExists`;
  `GetByTokenHash` returns `ErrInvalidRefreshToken`; OTP rate-limiting returns
  `ErrOTPRateLimited` — so every outcome is `errors.Is`-matchable.
- `allowed_domains` are lowercased on write, so domain matching is genuinely
  case-insensitive as documented.
- Read/list/get methods return the generic `ErrInternal` for real DB faults
  instead of leaking the wrapped driver/SQL error (sentinels still pass through).

## Documentation

- `SECURITY.md`: concrete private disclosure channel (GitHub Private Vulnerability
  Reporting + security email) and a `0.3.x` supported-versions table.
- `model` package: struct field-stability contract and the golang-jwt/v5 coupling
  on `JWTClaims`.
- Primary-read rationale on the auth-path lookups; tenant-authorization
  preconditions on the user-scoped revoke methods.

## Upgrading from 0.2.x

1. **Run migration `000002_uuid_consistency`** against your database.
2. Add a `Debug` method to any custom `logger.Logger` implementation.
3. Replace `userID.String()` with `userID` (a `uuid.UUID`) for `CreatedBy` fields
   and the `CreateInvitation` `createdBy` argument.
4. If you declared a value `authkit.AuthKit`, change it to `*authkit.AuthKit`.
5. If you imported `.../service` or `.../repository` directly (unsupported), move
   to the `AuthKit` accessor methods.

### Deliberately deferred

- **OTP hash-at-rest.** Codes are still stored as-is (no longer read back outside
  the locked consume path). Given they are 6-digit, single-use, attempt-locked,
  short-TTL, and auto-cleaned, hashing them at rest (which would require a column
  widening + a dedicated HMAC key) was judged low value for now and left for a
  later release.

## Verification

`gofmt`, `go vet` (default + `integration`), `golangci-lint`, and `gosec` are
clean; unit and PostgreSQL integration tests pass (including the new tests listed
in the CHANGELOG), with coverage enforced at ≥ 30% in CI.

---

Full changes: see [CHANGELOG.md](../../CHANGELOG.md). Licensed under [Apache-2.0](../../LICENSE).
