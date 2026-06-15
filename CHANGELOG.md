# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the library is pre-1.0 (`0.x`), minor releases may contain breaking changes.

## [Unreleased]

## [0.7.0] - 2026-06-14

API-ergonomics release. Consumers can now name the service types they're handed,
and user IDs and timestamps have one representation each at the API boundary.
Breaking (Go types only), as acceptable pre-1.0: the JSON wire format is
unchanged — `uuid.UUID` and `time.Time` marshal to the same string/RFC3339 they
did before. No schema change.

### Added

- **Public service interfaces in package `authkit`** (`AuthService`,
  `UserService`, `APIKeyService`, `TokenService`, `JWTService`, `OTPService`,
  `PasswordService`, `SecretService`, `TenantService`, `InvitationService`). The
  accessors return these, so a consumer can store a service on a struct field,
  pass it to a function, or mock it in a test — none of which the previous
  `internal`-package concrete return types allowed.

### Changed (breaking)

- **Accessors return interfaces** instead of `*service.X` (the concrete types live
  in an internal package and could never be named by consumers anyway).
- **User IDs are `uuid.UUID` at the API boundary.** `model.JWTClaims.UserID`,
  `model.ChangePasswordRequest.UserID`, and `model.RefreshResponse.UserID` are now
  `uuid.UUID` (were `string`); `AuthService.LogoutAll` and
  `TokenService.RevokeAllUserTokens` now take `uuid.UUID`. This matches the `User`
  entity and every `UserService` method, removing the string⇄UUID conversions
  consumers had to do. (JSON unchanged: `uuid.UUID` marshals to the same string.)
- **Response timestamps are `time.Time`.** `CreateAPIKeyResponse.CreatedAt`/
  `ExpiresAt` and `SaveSecretResponse.CreatedAt`/`UpdatedAt` are now `time.Time` /
  `*time.Time` (were pre-formatted RFC3339 strings); `SaveSecretResponse.CreatedBy`
  is now `uuid.UUID`. Callers can do time math without re-parsing; JSON output is
  unchanged.

`CreateAPIKeyRequest.ExpiresIn` stays `*string` — it accepts calendar units
(`"6M"`, `"1y"`) that `time.Duration` cannot represent.

### Security

- **Bumped `golang.org/x/crypto` to v0.52.0**, clearing the `golang.org/x/crypto/ssh`
  advisories Dependabot flagged (including a critical SSH auth-bypass). authkit-go
  only uses `golang.org/x/crypto/bcrypt`, so none were reachable
  (`govulncheck` reports 0 affected call paths), but the bump removes the alerts.
  The remaining advisories are Go standard-library ones — cleared by building with
  Go 1.25.10+ / 1.25.11+ rather than by any module change.

### Changed

- **Minimum Go is now 1.25** (required by `golang.org/x/crypto` v0.52.0).

## [0.6.0] - 2026-06-14

Correctness, security, and error-contract hardening from a full library review.
The error-handling changes make more failure modes matchable with `errors.Is`.
Some behavior changes (noted below) are breaking, as acceptable pre-1.0, but no
exported `authkit` function signatures changed and no migration is required.

### Security

- **Encrypted secrets no longer accept an unauthenticated ciphertext format.**
  `decrypt` now requires the `v1:` marker and always authenticates against the
  `(tenant_id, key)` AAD; the legacy prefix-less path is removed. Previously an
  attacker who could write the secrets column could strip the marker to bypass
  the context binding and relocate a value to another row. There are no released
  consumers, so no legacy ciphertext exists to migrate.

### Fixed

- **Status-change audit attribution is explicit, not inferred.** The
  `changed_by_type` of a `user_status_changes` row is now set from the operation's
  provenance — `system` only for the automatic failed-login lockout
  (`RegisterFailedLogin`), `admin` for every explicit admin mutation. Previously
  it was inferred from `failed_login_count >= 5`, so an admin locking a user who
  already had several failed attempts was mis-recorded as `system`.
- **`ValidateInvitation` no longer returns an error for a normally-invalid
  invitation.** An unknown, expired, or exhausted invitation is reported as
  `(false, nil)`; the error is reserved for genuine storage faults (sanitized). A
  caller branching on `err != nil` no longer treats an expired invite as a 500.
- **`errors.Is(err, ErrNotFound)` now matches the id/name-scoped mutators.**
  `Update`, `SetPassword`, `IncrementTokenVersion`, `IncrementFailedLoginCount`,
  `UpdateLastLogin`, `UpdateRolesByTenant`, API-key/secret/tenant/invitation/
  refresh-token deletes, and the OTP delete now wrap `model.ErrNotFound` instead
  of returning a bare string.

### Changed (breaking)

- **Admin `Lock` no longer increments `failed_login_count`.** An explicit admin
  lock is now identical to `LockByTenant`: it sets the locked state without
  touching the failed-login counter (which tracks authentication attempts, not
  admin actions).
- **`AddAllowedDomain` is now idempotent.** Adding a domain that is already
  present succeeds (and touches `updated_at`) instead of returning an error; a
  zero-row result now unambiguously means the tenant does not exist
  (`ErrNotFound`).

### Added

- `ErrPasswordTooWeak` — strength failures (too short, too long, missing a
  required character class) are now matchable. `PasswordStrengthRequirements`
  gains a `MaxLength` (default 72, bcrypt's input cap); over-cap passwords are
  rejected as a clean validation error, including via `HashPassword` for callers
  that bypass `ValidatePasswordStrength`.
- `ErrSecretEncryptionKeyMissing` — a missing/invalid `SecretConfig.EncryptionKey`
  now surfaces from the first `SecretService` operation as a matchable sentinel
  instead of an opaque internal error.
- `CreateInvitation` maps the (astronomically rare) server-minted-code collision
  to `ErrInternal` instead of leaking the raw constraint string.

## [0.5.0] - 2026-06-14

Identifier-generation overhaul and a migration consolidation. Because no released
version has a consumer yet, the migration set is collapsed to a single
`000001_identity_schema` that represents the final schema — **apply it to a fresh
database** (this is the baseline schema, not an in-place upgrade from an earlier
0.x). Breaking, as acceptable pre-1.0.

### Changed (breaking)

- **UUIDv7 is minted in Go for every id; the schema has no SQL-side UUID
  generation.** All `id`/`family_id` column defaults, the `uuid_generate_v7()`
  generator, and the now-unused `pgcrypto` extension are removed. The application
  supplies every id with `uuid.NewV7()`.
- **Account status-change audit is written by the application, not a DB trigger.**
  The `record_status_change` trigger is gone; the repository writes
  `user_status_changes` rows in Go, in the same transaction as the status change.
  Semantics are preserved exactly (one row per real `is_enabled`/`is_locked`
  transition; same `status_type`, `changed_by_type`, and metadata; `changed_by`
  NULL). The status mutators (`Enable`/`Disable`/`Delete`/`Lock`/`Unlock` and their
  `*ByTenant` variants, plus the failed-login lockout) are now transactional.
- **Migrations consolidated to one file.** The 000002/000003/000004 migrations are
  folded into `000001_identity_schema`; the standalone files are removed.

### Removed

- The `auth_events` table (never written or read by the library).
- `uuid_generate_v7()`, the status-change trigger + function, all UUID column
  defaults, and the `pgcrypto` extension.

### Upgrading

Apply the single `000001_identity_schema.up.sql` to a fresh database. There are no
released consumers; anyone who applied an earlier 0.x schema should recreate it
from the new 000001.

## [0.4.1] - 2026-06-13

Bug-fix and hardening release on top of v0.4.0. No public API or behavior
changes for correctly-configured callers; backward-compatible (the AES-GCM AAD
change still decrypts existing ciphertext). Includes one new, safe migration.

### Security

- **Secret encryption is now context-bound.** AES-256-GCM ciphertext is
  authenticated against its `(tenant_id, key)` via the GCM additional
  authenticated data, so a value relocated to another row (e.g. by DB tampering
  under the shared key) fails authentication instead of decrypting as another
  tenant's secret. Backward-compatible: legacy ciphertext (written before this
  change) still decrypts; new writes carry a `v1:` marker. No re-encryption
  migration is required.
- **OTP generation rate limit is now enforced atomically** inside the upsert (a
  conditional `ON CONFLICT … WHERE created_at <= cutoff`), closing the
  check-then-write TOCTOU where two concurrent requests could each issue a code.
- **`ChangePassword` reads the current password hash from the primary**, not a
  read replica, removing a read-after-write window in the old-password auth gate.
- **`maskValue` fully masks values shorter than 12 characters** (was 8), so a
  short secret can't expose most of itself via the prefix + last-4 reveal.
- **Background "last used" updates are bounded** by a semaphore (max 64 in
  flight); a burst of token/API-key validations can no longer fan out unbounded
  goroutines contending on the write pool.

### Fixed

- **Refresh rotation no longer flags an expired token as reuse/theft.** An
  expired-but-never-consumed refresh token is no longer marked revoked, so
  re-presenting it reports "expired" rather than tripping family-wide reuse
  revocation (which stays reserved for genuinely consumed/rotated tokens).
- **`New()` rejects an out-of-range bcrypt cost** (outside 4–31) instead of
  silently coercing it to the default — a misconfigured cost now fails fast.
- **`UserService.List` clamps `limit`/`offset`** (non-positive limit → default
  50, capped at 1000, negative offset → 0) so caller-supplied paging can't
  request an unbounded scan or an invalid SQL `LIMIT`.
- **Secret `Save`/`List`/`Delete`/`MarkVerified`/`CountByTenant` sanitize errors**
  through the same `ErrInternal` boundary as the read paths, so a genuine DB
  fault no longer surfaces raw driver text.
- **`TenantService.CreateTenant` / `SetAllowedDomains` reject an empty
  `allowed_domains` list** up front instead of surfacing a raw NOT NULL / CHECK
  violation.
- Doc/comment fixes: the `ValidateAPIKey` README example no longer shadows the
  `context` package; `GenerateRefreshToken` godoc says HMAC-SHA256 (not SHA256).

### Added

- **Migration `000003_drop_redundant_api_key_hash_index`**: drops the redundant
  `idx_api_keys_key_hash` index (`api_keys.key_hash` is already `UNIQUE`-indexed).
- Tests: INET `ip_address` round-trip, `api_keys` UUID `key_id` round-trip + the
  000003 index state, OTP atomic rate-limit, and AES-GCM AAD (wrong-context
  fails, legacy ciphertext decrypts).

### Documentation

- The README "Error Handling" section and the `patterns.md` JWT middleware now
  document the sentinel-error contract: branch with `errors.Is`, map account
  states to 403 and `ErrInternal`/unexpected errors to 500 (not a blanket 401).

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

[Unreleased]: https://github.com/modgudinc/authkit-go/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/modgudinc/authkit-go/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/modgudinc/authkit-go/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/modgudinc/authkit-go/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/modgudinc/authkit-go/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/modgudinc/authkit-go/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/modgudinc/authkit-go/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/modgudinc/authkit-go/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/modgudinc/authkit-go/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/modgudinc/authkit-go/releases/tag/v0.1.0
