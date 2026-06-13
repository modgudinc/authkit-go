# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the library is pre-1.0 (`0.x`), minor releases may contain breaking changes.

## [Unreleased]

## [0.4.0] - 2026-06-13

Database-driver release: the library now runs on **pgx**
(`github.com/jackc/pgx/v5`) instead of `lib/pq`, and `lib/pq` is dropped as a
dependency. The Go API is **unchanged** — `Config.DatabaseConnection` still takes
`*sql.DB` and no `authkit` signatures changed — but because the repository layer
now relies on pgx's driver behavior, **consumers must use the pgx driver**. That
driver swap is the only upgrade step; it is flagged breaking per SemVer because
existing `lib/pq` callers must change their connection setup.

### Changed (breaking)

- **PostgreSQL driver is now pgx.** The library is still built on `database/sql`,
  so `Config` continues to accept `*sql.DB` — but register the pgx driver and open
  with the `pgx` driver name instead of `lib/pq`:
  ```go
  import _ "github.com/jackc/pgx/v5/stdlib"
  db, err := sql.Open("pgx", dsn) // was: _ "github.com/lib/pq"; sql.Open("postgres", dsn)
  ```

### Removed

- The `github.com/lib/pq` dependency. `github.com/jackc/pgx/v5` is now the only
  PostgreSQL driver dependency (no change to the Go version requirement).

### Internal

- `tenants.allowed_domains` (`text[]`) is now written with native `[]string`
  parameters and read via `array_to_json(...)::text` + `encoding/json`, because
  pgx's `database/sql` layer does not scan a Postgres array directly into a Go
  `[]string`.
- Duplicate-user / invitation conflict detection (`ErrUserExists`) now matches
  `*pgconn.PgError` instead of `*pq.Error`.
- Schema-identifier quoting uses `pgx.Identifier{}.Sanitize()` instead of
  `pq.QuoteIdentifier`; integration tests use the pgx `stdlib` driver.

## [0.3.0] - 2026-06-12

Security-hardening, error-contract, and API/consistency release covering every
remaining high-confidence item from the OSS-readiness review. Includes several
**breaking changes** (acceptable pre-1.0) and a new database migration. See
"Upgrading" below.

### Added

- `model.ErrUserExists`, `model.ErrOTPRateLimited`, and `model.ErrInternal`
  (re-exported as `authkit.Err*`): a duplicate-user/invitation conflict, an OTP
  requested before its rate-limit window elapsed, and a generic internal/storage
  fault, respectively — so callers can branch with `errors.Is` and driver/schema
  details do not leak across the API boundary.
- Access tokens now carry a `jti` (unique token ID) for log correlation and
  future per-token revocation.
- Migration `000002_uuid_consistency`: types `api_keys.key_id` as `UUID` (it
  holds a UUIDv7) and switches id-column defaults to a new time-ordered
  `uuid_generate_v7()` generator, so DB-default and trigger-populated rows
  (`user_status_changes`, `auth_events`) are no longer UUIDv4.
- `logger.Logger` gains a `Debug` level for verbose/lower-sensitivity diagnostics.

### Changed (breaking)

- The `service` and `repository` packages moved under `internal/` and are no
  longer importable by consumers. Use `AuthKit`'s accessor methods
  (`AuthService()`, `UserService()`, …) — the supported entrypoint — instead.
- `authkit.New` now returns `*AuthKit` (was `AuthKit`), matching its
  pointer-receiver methods.
- `Logger` now requires a `Debug(msg string, fields ...interface{})` method;
  custom implementations must add it. A nil `Config.Logger` now defaults to
  `logger.NopLogger` (the library never holds a nil logger).
- `CreatedBy` is now `uuid.UUID` (was `string`) on `model.APIKey`,
  `model.Invitation`, `model.Secret`, and their request structs; the `createdBy`
  parameter of `InvitationService.CreateInvitation` is now `uuid.UUID`.
- `model.InsertAPIKeyParams` was removed from the public `model` package (it was
  an internal repository DTO). Create API keys via `APIKeyService.CreateAPIKey`
  with `model.CreateAPIKeyRequest`.

### Security

- `AuthService.ChangePassword` no longer reports success if session revocation
  fails after the password is written: it now returns an error (the password is
  changed but old access/refresh tokens were not revoked), so callers can force a
  re-login instead of silently leaving old sessions valid.
- OTP generation's rate-limit check now reads from the primary (not a read
  replica), so replication lag cannot let a just-issued code bypass the limit, and
  no longer fails open — a transient DB read error is surfaced instead of silently
  disabling the limit.
- Email addresses are masked in the library's logs (`u***@acme.com`), and the
  login "user not found" path no longer logs the raw lookup error, so auth logs
  are not an account-enumeration list.
- The failed-login lockout decision is now made atomically in the database
  (a single `UPDATE ... RETURNING`), so concurrent failed logins can no longer
  trip the lockout one attempt early or late.

### Fixed

- `JWTService.ValidateAccessToken` now wraps `model.ErrInvalidToken` on all
  failure paths (parity with `AuthService.ValidateJWT`), so consumers using the
  JWT service directly can branch with `errors.Is(err, ErrInvalidToken)`.
- Creating a user (`Repository.Create`) or accepting an invitation
  (`Repository.AcceptInvitation`) for an already-existing `(tenant_id, email)` now
  returns `ErrUserExists` instead of leaking a raw Postgres unique-violation
  string. The invitation is not consumed (the transaction rolls back).
- `Repository.GetByTokenHash` returns `ErrInvalidRefreshToken` for unknown or
  expired tokens instead of leaking `sql.ErrNoRows` / a bare error, matching every
  sibling lookup.
- OTP generation rate-limiting returns the new `ErrOTPRateLimited` sentinel
  instead of a string-only error.
- `allowed_domains` are normalized to lowercase on write (`CreateTenant`,
  `SetAllowedDomains`, `AddAllowedDomain`), so domain matching is genuinely
  case-insensitive as documented (a tenant configured with `Acme.com` is now
  matched by `acme.com`).
- `UserService` (`GetByID`/`GetByEmail`/`List`), `APIKeyService`
  (`ListAPIKeys`/`GetAPIKey`/`RevokeAPIKey`/`CountByTenant`/`CleanupExpiredKeys`),
  and `SecretService.GetSecret` now return `ErrInternal` for genuine DB faults
  instead of leaking the wrapped driver/SQL error; known sentinels (e.g.
  `ErrNotFound`) still pass through for `errors.Is`.
- `JWTService.ValidateAccessToken` docstring no longer mislabels bcrypt as a
  "constant-time comparison"; the OTP rate-limit read no longer selects the
  plaintext code back from the database.

### Changed

- Repository query strings use a `{{schema}}` placeholder for schema substitution
  instead of a blanket `"authkit."` string replacement, so a future comment or
  string literal containing `authkit.` cannot be silently rewritten. Internal
  only; no API or behavior change.

### Documentation

- `SECURITY.md` now documents a concrete private disclosure channel (GitHub
  Private Vulnerability Reporting + a security email) and the supported-versions
  table tracks `0.3.x`.
- `model` package doc states the struct field-stability contract (append-only,
  keyed literals, returned values are read-only snapshots); `JWTClaims` documents
  the golang-jwt/v5 SemVer coupling from its embedded `RegisteredClaims`.
- `GetByTokenHash`/`GetAPIKeyByHash` document why they read the primary;
  `RevokeAllUserTokens`/`LogoutAll`/`GetByUserID`/`DeleteByUserID` document the
  caller-owned tenant-authorization precondition.

### Tests

- New: atomic failed-login lockout, the JWT `ErrInvalidToken` sentinel,
  `DummyVerify` timing-equalization, the real expired-OTP consume path,
  duplicate-user/invitation (`ErrUserExists`), the refresh-token-hash sentinel,
  case-insensitive domain matching, and migration `000002`.
- Fixed a non-deterministic AES-GCM tamper test (it could spuriously pass ~1 in
  3500 runs) and removed dead code in the mask-value test.

### Upgrading from 0.2.x

- **Run migration `000002_uuid_consistency`** after upgrading.
- If you implement `logger.Logger`, add a `Debug` method.
- `New` returns `*AuthKit`: `kit, err := authkit.New(...)` is unchanged, but a
  `var kit authkit.AuthKit` declaration must become `*authkit.AuthKit`.
- Pass a `uuid.UUID` (not a string) for `CreatedBy` fields and the
  `CreateInvitation` `createdBy` argument (e.g. `userID` instead of
  `userID.String()`).
- If you imported `.../service` or `.../repository` directly (unsupported), switch
  to the `AuthKit` accessor methods.
- `ChangePassword` may now return an error when post-update session revocation
  fails (previously it returned `nil`); the password is changed, so force a
  re-login on that error.

## [0.2.1] - 2026-06-11

### Security

- `UserService.DisableByTenant` now revokes the user's refresh tokens (parity with
  `Disable`, which delegates to it), so disabling an account terminates its
  sessions and a later re-enable cannot resurrect pre-disable refresh tokens.

### Documentation

- Documented that `CreateInvitation` / `AcceptInvitation` do **not** enforce the
  tenant's `allowed_domains` (call `TenantService.ValidateDomainAccess` if you
  need it); the README invitation flow example shows the optional domain check.
- Updated `docs/patterns.md` to recommend the atomic `AcceptInvitation` for
  invitation signup instead of the manual validate/create/increment sequence.

## [0.2.0] - 2026-06-11

Security-hardening follow-up to 0.1.0. Includes one breaking change (removal of
`Repository.VerifyCode`).

### Removed (breaking)

- `Repository.VerifyCode` — a read-only OTP check that did not consume the code,
  count attempts, or scope by purpose, and was an auth footgun if called directly.
  Use `ConsumeVerificationCode` (via `OTPService.Validate`) for the auth path.

### Security

- Role/user updates (`UpdateByTenant`, `UpdateRolesByTenant`) now bump
  `token_version`, so a role downgrade immediately invalidates outstanding access
  tokens (which embed roles); the next refresh re-issues correctly-scoped tokens.
- `TokenService.ValidateRefreshToken` now rejects disabled/locked accounts,
  matching the rotation path, so it is safe even if a consumer uses it directly.

### Documentation

- `AcceptInvitation` is now the documented signup path in the README and
  `docs/examples.md`; the manual `ValidateInvitation` + `IncrementUseCount`
  sequence is marked as a lower-level building block with a TOCTOU warning.

### Tests

- Integration tests for the role-update `token_version` bump and for
  `ValidateRefreshToken` rejecting an inactive account.

## [0.1.0] - 2026-06-10

First tagged release. Establishes the multi-tenant identity/auth surface
(users, tenants, JWT + refresh tokens, API keys, OTP, invitations, encrypted
secrets) on PostgreSQL, plus a security-hardening pass across the library.

### Added

- Exported sentinel errors (`model.Err*`, re-exported as `authkit.Err*`) so
  callers can branch with `errors.Is` instead of matching error strings.
- `InvitationService.AcceptInvitation` / `Repository.AcceptInvitation`: validate,
  consume, and create the user in a single transaction, bound to the invitation's
  target email and roles.
- Refresh-token reuse/theft detection via a token `family_id`; presenting an
  already-consumed token revokes the whole family (`model.ErrRefreshTokenReuse`).
- Per-OTP failed-attempt lockout (`MaxOTPValidationAttempts`) and constant-time
  OTP comparison.
- Minimum-length validation (`MinSecretLength`, 32 bytes) for JWT/HMAC secrets in `New()`.
- Optional JWT issuer/audience: `JWTConfig.Issuer` / `JWTConfig.Audience` (and
  `service.WithIssuer` / `service.WithAudience`); when set they are stamped on
  generated tokens and required during validation.
- `logger.NopLogger`, a safe no-op `Logger` implementation.
- Unit tests for security-critical auth paths (login lockout/enumeration,
  `ValidateJWT` revocation/disabled/locked, JWT `alg=none` rejection) and
  integration tests for refresh-token reuse and atomic invitation acceptance.
- `REVIEW.md` capturing the OSS-readiness review.
- Configurable identity schema with validated, quoted schema names.
- Docker Compose and opt-in integration tests that validate migrations against PostgreSQL.

### Changed (breaking)

- `OTPService.Generate/Validate/Delete` now take a `tenantID` first argument;
  `verification_codes` is keyed by `(tenant_id, email, purpose)` with a
  `tenant_id` foreign key (OTPs isolated per tenant and per purpose).
- `APIKeyService.GetAPIKey`/`RevokeAPIKey` (and the underlying repository methods)
  now require and are scoped by `tenantID`.
- `UserService.Update/Delete/Enable/Disable/Lock/Unlock/SetPassword/IncrementTokenVersion`
  now take a `tenantID` and are scoped to it; account-cutting actions revoke the
  user's refresh tokens.
- `model.CreateRefreshTokenRequest` gains `FamilyID`; `ConsumeVerificationCode`
  returns `model.OTPConsumeResult`.
- Renamed the project/package surface to authkit-go/authkit and switched the
  default database schema to `authkit`.

### Security

- Login no longer leaks account existence/state: unknown-user and disabled/locked
  paths perform a dummy bcrypt comparison (timing equalization) and return a single
  generic `model.ErrInvalidCredentials`; the specific reason is logged only.
- The token refresh path re-checks account status (enabled/locked/version) before
  minting a new access token; disable/lock/version-bump revoke refresh tokens.
- Refresh-token rotation is atomic (old token consumed and replacement stored in
  one write-side transaction).
- Repository not-found paths (users, tenants, API keys, invitations, OTPs,
  secrets) return `model.ErrNotFound` instead of raw driver errors.
- JWT validation pins the exact algorithm (`HS256`), requires an `exp` claim, and
  applies a clock-skew leeway.
- Email is normalized (trimmed + lowercased) at login, user creation, lookups, and
  OTP operations, so casing/whitespace can't fork or hide accounts.
- Token/API-key validation failures (untrusted input) are logged at Warn instead
  of Error to prevent log floods.
- Fire-and-forget "last used" timestamp updates run on a cancellation-detached
  context (`context.WithoutCancel`) with a timeout, so they survive request
  completion without ignoring cancellation or hanging (gosec G118).

### Fixed

- README/`docs` examples referenced request types under the `service` package
  (they live in `model`); call sites updated for the new tenant-scoped signatures.
- OTP logging is safe when no logger is configured; OTP purpose is enforced during validation.
- `model.Secret` `db` struct tags now match the `provider_keys` columns.

### CI

- Integration tests now produce a cross-package coverage profile and the build
  fails if total coverage drops below 30%.

[Unreleased]: https://github.com/modgudinc/authkit-go/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/modgudinc/authkit-go/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/modgudinc/authkit-go/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/modgudinc/authkit-go/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/modgudinc/authkit-go/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/modgudinc/authkit-go/releases/tag/v0.1.0
