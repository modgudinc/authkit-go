# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the library is pre-1.0 (`0.x`), minor releases may contain breaking changes.

## [Unreleased]

## [0.12.0] - 2026-06-21

Production-readiness hardening from a multi-dimension audit: closes the medium-
severity policy/observability gaps and a high-severity documentation defect. Includes
breaking changes (a new required-when-used config secret, a schema change, and two new
`UserService` interface methods), so this is a minor (`0.x`) bump.

### Security

- **OTP codes are now stored as a keyed HMAC-SHA256, never in plaintext.** A new
  `OTPConfig.HMACSecret` keys the hash (mirroring refresh tokens and API keys), so a
  read-only database/backup/replica disclosure no longer yields usable codes. The
  `verification_codes.code` column is renamed to `code_hash` (`VARCHAR(64)`).
- **Refresh-token reuse detection now invalidates outstanding access tokens.** On a
  detected reuse/theft, the rotation transaction bumps the user's `token_version`
  (in addition to revoking the whole token family), so `ValidateJWT` rejects every
  already-issued access token immediately instead of letting them live to their `exp`.
- **`ChangePassword` now gates on account status.** A disabled or locked account can no
  longer rotate its own password mid-freeze (returns `ErrAccountDisabled` /
  `ErrAccountLocked`), matching the `Login` and `ValidateJWT` gates.

### Added

- **Optional metrics seam (`metrics` package + `Config.Metrics`).** A minimal, no-op-by-
  default `Metrics` interface, called at key decision points: login success/failure,
  account lockout, OTP failure/lockout, and refresh-token reuse. Canonical counter names
  are exported as `metrics.Counter*`. Survives independently of log level — recommended
  for alerting.
- **`UserService.StatusHistory`** reads a user's status-change audit trail (tenant-scoped),
  and **`UserService.CleanupStatusChanges`** prunes it by age — the `user_status_changes`
  table previously had no read API and no retention method (unbounded growth).
- **Distinguishable refresh-reuse event.** Reuse/theft is now logged as a dedicated
  elevated event (`event=refresh_token_reuse`, with user/family ids via the new
  `model.RefreshTokenReuseError`) and metered, instead of a generic warning.
- **`ErrOTPSecretMissing`** sentinel, returned by `OTPService.Generate`/`Validate` when
  no `OTPConfig.HMACSecret` is configured.

### Changed (breaking)

- **`OTPConfig.HMACSecret` is required when `OTPService` is used.** It is validated for
  length at construction when set; `Generate`/`Validate` return `ErrOTPSecretMissing`
  when absent. Callers using OTP must configure it.
- **Schema change — re-apply migration `000001`.** `verification_codes.code` →
  `code_hash VARCHAR(64)`, and the unused `idx_user_status_changes_changed_by` index is
  dropped. (Any existing OTP rows are ephemeral and need not be migrated.)
- **`UserService` interface gains `StatusHistory` and `CleanupStatusChanges`.** Code that
  implements/mocks the interface must add these methods.

### Fixed

- **README showed `tokenService.RevokeAllUserTokens`**, a method intentionally removed
  from the public `TokenService` (it scoped by `user_id` with no tenant check). Replaced
  with the tenant-safe `authService.LogoutAll`.
- **The integration CI job now runs with `-race`**, so the detached `last_used` fan-out
  (the only concurrent goroutine in non-test source, exercised only by the integration
  suite) is covered by the race detector.
- Doc drift: `model` package overview named a non-existent `RefreshToken` type and the
  pre-0.11 `GetTenant` method; the README sentinel list omitted `ErrValueTooLong`.

### Documentation

- Documented that several security signals (OTP lockout, refresh-token reuse, sub-
  threshold failed logins) are logger-only and lost if no `Logger`/`Metrics` is injected.
- Documented required connection-pool limits and server-side `statement_timeout`/
  `lock_timeout` as caller-owned controls (README + SECURITY.md), moved pool config into
  the primary quickstart, and added OTP-storage / OTP-secret / metrics guidance.
- Replaced the drift-prone supported-versions table in SECURITY.md with a "latest minor
  only" policy statement.

## [0.11.1] - 2026-06-18

A patch release with internal-only cleanups — no public API, behavior, or schema
change. Safe to upgrade from v0.11.0 with no code changes.

### Internal

These are non-behavioral cleanups (no public API or schema change).

- **The integration test suite is now lint-clean and gated.** Fixed pre-existing
  `errcheck` (`db.Close`/`rows.Close`), a missing `rows.Err()` check, and gosec
  G304/G101 false-positives in the `//go:build integration` tests, and set
  `run.build-tags: [integration]` in `.golangci.yml` so `golangci-lint run` (CI and
  `make lint`) now also lints those files instead of skipping them.
- **Split the user status-change audit machinery out of `identity.go`** into
  `identity_audit.go` (the `statusChangeActor`/`userStatusSnapshot` types and the
  `withUserStatusAudit`/`readUserStatusForUpdate`/`recordStatusChange`/
  `insertUserStatusChange` helpers), reducing `identity.go` to user CRUD/queries.

## [0.11.0] - 2026-06-18

Breaking API-ergonomics cleanup — service methods are renamed to bare, namespaced
verbs, `UserService` duplicate methods are removed, and `Update` takes its ids in the
request struct — bundled with the security, correctness, and hardening work since
v0.10.0. No schema migration is required.

### Security

- **`AuthService.ValidateJWT` now reads the user from the primary, not a read replica.**
  The `token_version` revocation check (and the `is_enabled`/`is_locked` account-status gate) is
  the library's only immediate session-revocation mechanism, but it read from the read-only
  replica while `LogoutAll` and `ChangePassword` write the bumped `token_version` to the primary.
  Under replication lag, a just-revoked access token (or a just-disabled/locked account) kept
  passing validation until the replica caught up — a fail-open window. The gate now reads the
  primary via a new internal `Repository.GetByIDFromPrimary`, matching the existing read-write
  decision already used for refresh-token and API-key validation. Deployments where the RO and RW
  handles are the same `*sql.DB` were never affected.

- **`AuthService.Login` now reads its account-status gate from the primary.** The
  `is_enabled`/`is_locked` check (and the post-auto-unlock re-read) previously came from the read
  replica, so an admin disable/lock — or an auto-lock just written by `RegisterFailedLogin` — was
  invisible to the front-door gate during replication lag, allowing a few extra logins against a
  just-locked/disabled account. The gate now reads the primary via `Repository.GetByEmailFromPrimary`
  / `GetByIDFromPrimary`. (The authoritative lockout *counter* was already enforced on the primary
  and was never evadable.)

- **`APIKeyService.CreateAPIKey` no longer leaks raw driver errors.** A database fault (e.g. an FK
  or unique-constraint violation from a bad `tenant_id`/`created_by`) was returned verbatim,
  exposing table/constraint names and SQLSTATE to the caller. It now routes through `sanitizeError`
  like every other create method — logged server-side, returned as `ErrInternal` — while known
  sentinels still pass through for `errors.Is`.

- **An OTP attempt-lockout no longer resets the generation rate-limit window.** Reaching the
  failed-attempt cap (`MaxOTPValidationAttempts`) used to delete the code row; because the
  per-`(tenant, email, purpose)` generation cooldown is keyed on that row's `created_at`, a burst
  of wrong guesses (or any lockout) wiped the cooldown and allowed fresh OTP emails to be issued on
  demand (cost/spam amplification). The locked-out row is now retained as a tombstone so the
  cooldown stays in force; it is replaced by the next generation once the cooldown elapses and
  removed by `CleanupExpired` at expiry. (Behavior change: a user who locks out a code may now have
  to wait out the cooldown before a new code is issued, instead of immediately.)

- **`PasswordService.DummyVerify` no longer latches a generation failure.** The dummy bcrypt hash
  used to equalize login timing (preventing username enumeration) was memoized with `sync.Once`, so
  a single failed generation would silently disable the equalizer for the process lifetime. It now
  re-attempts generation on a later call (mutex-guarded, still computed at most once on success), so
  a transient failure cannot permanently reopen the timing side channel. No behavior change on the
  normal path.

- **Single-session logout now soft-revokes the refresh token instead of deleting it.**
  `AuthService.Logout` / `TokenService.RevokeRefreshToken` previously hard-deleted the token row, so
  replaying a stolen-then-logged-out token read as a benign invalid token rather than triggering
  reuse/theft detection. The row is now retained with `revoked_at` set (and reaped by
  `CleanupExpiredTokens` at expiry), so a later replay trips `ErrRefreshTokenReuse` and revokes the
  whole token family — the same guarantee token rotation already provided. Logout remains idempotent.

### Changed (breaking)

- **Service methods renamed to bare, namespaced verbs (#14).** Each service already
  namespaces its noun, so the type suffix was redundant:
  `APIKeyService`: `CreateAPIKey`→`Create`, `ValidateAPIKey`→`Validate`, `ListAPIKeys`→`List`,
  `GetAPIKey`→`Get`, `RevokeAPIKey`→`Revoke`, `CountByTenant`→`Count`, `CleanupExpiredKeys`→`CleanupExpired`;
  `TenantService`: `CreateTenant`→`Create`, `GetTenant`→`Get`, `GetTenantByDomain`→`GetByDomain`,
  `ListTenants`→`List`, `TenantExists`→`Exists`;
  `InvitationService`: `CreateInvitation`→`Create`, `GetInvitation`→`Get`, `ListInvitations`→`List`,
  `ListActiveInvitations`→`ListActive`, `ValidateInvitation`→`Validate`, `AcceptInvitation`→`Accept`,
  `RevokeInvitation`→`Revoke`, `DeleteInvitation`→`Delete`, `CleanupExpiredInvitations`→`CleanupExpired`;
  `SecretService`: `SaveSecret`→`Save`, `GetSecret`→`Get`, `ListSecrets`→`List`, `DeleteSecret`→`Delete`,
  `CountByTenant`→`Count`; `TokenService`: `CleanupExpiredTokens`→`CleanupExpired`. Each is a pure
  rename (same args, same behavior); `model.*Request`/`*Response` type names are unchanged.

- **`UserService`: duplicate methods removed and `ByTenant` suffix dropped (#6).** The duplicate
  `Enable`/`Disable` aliases are removed and `EnableByTenant`→`Enable`, `DisableByTenant`→`Disable`,
  `CountByTenant`→`Count`, `UpdateRolesByTenant`→`UpdateRoles` (every `UserService` mutator is already
  tenant-scoped, so the suffix signalled nothing).

- **`UserService.Update` takes its ids in the request struct (#13).** Signature changes from
  `Update(ctx, userID, tenantID, req)` to `Update(ctx, req)`; `model.UpdateUserRequest` gains
  `UserID` and `TenantID`. This matches `Create` and `ChangePassword` (create/update take a keyed
  request struct; simple get/delete/status ops take positional ids).

- **`TokenService.RevokeAllUserTokens` is removed from the public `TokenService` interface.**
  It scopes by `user_id` only (refresh tokens carry no tenant column), so calling it with a
  caller-supplied id and no prior tenant-ownership check was a cross-tenant authorization gap
  (one tenant could force-log-out another tenant's user). Use
  `AuthService.LogoutAll(ctx, userID, tenantID)` instead, which proves tenant membership first
  (and also invalidates access tokens). The method remains available internally for `LogoutAll`.

### Fixed

- **`OTPService.Generate` now rejects a non-positive `ExpirationDuration`.** A zero value (the
  zero value of an omitted field) or a negative duration previously minted a code that was already
  expired the instant it was issued — impossible to validate, yet returned to the caller as
  success while still consuming the generation rate-limit window. It now returns a clear error up
  front, mirroring the positive-expiry check already enforced by `CreateAPIKey`.

- **`AuthService.ChangePassword` now updates the password and bumps `token_version` atomically.**
  The password write and the access-token-invalidating `token_version` bump are now a single
  tenant-scoped UPDATE (`SetPasswordAndBumpTokenVersionByTenant`) rather than two separate writes, so
  they can never be left half-applied (e.g. password changed but old access tokens still validating).
  Refresh-token revocation remains a follow-up step whose failure is still surfaced as an error (an
  undeleted refresh token stays usable until expiry); on that failure, retry via `LogoutAll`.

- **`InvitationService.CreateInvitation` now validates its inputs.** It rejects an empty or
  malformed target email (previously stored verbatim and later bound onto the created account by
  `AcceptInvitation`) and a `MaxUses` above `MaxInvitationUses` (1000), which would mint an
  effectively unlimited signup link. The email is normalized before the structural check.

- **Over-length string inputs now surface as a matchable error instead of `ErrInternal`.** A value
  exceeding its column width (e.g. an over-long tenant_id, name, secret key, email, or display name)
  produced a Postgres SQLSTATE 22001 that `sanitizeError` collapsed into the opaque `ErrInternal`.
  It is now mapped to a new sentinel, `ErrValueTooLong` (re-exported as `authkit.ErrValueTooLong`),
  so callers can `errors.Is` it and return a 400. `TenantService.UpdateSettings` additionally rejects
  a serialized settings blob larger than `MaxTenantSettingsBytes` (1 MiB) with the same sentinel.

### Fixed (schema / CI)

- **The `allowed_domains` non-empty CHECK now actually rejects an empty array.** It used
  `array_length(allowed_domains, 1) > 0`, which is `NULL` (not `FALSE`) for `'{}'` and so passed
  the constraint; it now uses `cardinality(allowed_domains) > 0`. (The service layer already
  rejected an empty list, so this is a schema-correctness/defense-in-depth fix.)
- **Dropped two redundant indexes from the initial migration** — `idx_refresh_tokens_token_hash`
  (the `token_hash UNIQUE` constraint already provides that index) and
  `idx_verification_codes_tenant_email` (a left-prefix of the `(tenant_id, email, purpose)` PK).
  Both edits are in the consolidated `000001` migration; a fresh `migrate up` gets the corrected
  schema (existing deployments are unaffected and may drop them manually).
- **Hardened the gosec CI step**: explicit `-severity`/`-confidence` thresholds (so a future
  default change can't silently relax the gate) plus SARIF output uploaded as a build artifact for
  triage history.
- **Added `.github/dependabot.yml`** (gomod + github-actions, weekly) so the already-whitelisted
  `dependabot/*` branches actually get created for security-sensitive dependency bumps.

### Documentation

- **Documented that login/refresh rate limiting is caller-owned.** `AuthService.Login` enforces
  only a per-account failed-login lockout, which does not stop password spraying across accounts;
  `RefreshToken` has no built-in throttle. Added a "Caller-Owned Controls" section to SECURITY.md
  and security notes to the `Login`/`RefreshToken` godoc making clear the embedding application
  must provide IP/global rate limiting.

- **Documented several defense-in-depth assumptions.** The secret-encryption design (random GCM
  nonces under a single long-lived key, safe at expected scale; no built-in key-rotation helper) is
  now noted at `SecretService.encrypt`; that access tokens carry the user's email in signed-but-not-
  encrypted claims (so raw tokens must not be logged) and that injected line-oriented loggers should
  escape caller-supplied fields are noted in SECURITY.md; and that `GetTenant`/`GetTenantByDomain`/
  `ListTenants` return the full, unauthorized `Settings` blob is noted on the `TenantService` interface.

- **Added a "Generating secrets" section to the README** with `openssl rand -base64 32` snippets and
  a note that `SecretConfig.EncryptionKey` must *decode* to 32 bytes (a 32-char ASCII string is wrong).

- **Documented that `GenerateAccessToken`/`GenerateTokenPair` require a complete, freshly loaded
  `*model.User`** — a partial/hand-built user (e.g. zero `TokenVersion`) mints a token that
  `ValidateJWT` treats as revoked. Noted on the methods and the `JWTService`/`TokenService` interfaces.

- **Corrected the accessor cost guidance** (`AuthKit` service accessors): the doc no longer says
  "either is fine" — each call allocates a fresh service (and dependency graph), so callers should
  prefer reusing a constructed service over calling the accessor on hot paths.

- **Fixed inaccurate docs**: `architecture.md` described OTP consumption as `DELETE ... RETURNING`,
  but it is `SELECT ... FOR UPDATE` then `DELETE` in a transaction; the down migration now documents
  the schema-name substitution rule (matching the up migration).

- **`OTPService` logging** now uses `err.Error()` for the `error` field, matching the rest of the
  package (was passing the raw error value at a few call sites).

### Internal

These are non-behavioral cleanups with no public API change; listed for completeness.

- **Removed ~176 redundant `if s.logger != nil` guards** across the service layer. Each service
  constructor now defaults a nil logger to a no-op logger (`ensureLogger`), so call sites log
  unconditionally.
- **Standardized `sanitizeError` to always receive the service logger.** Previously some paths
  passed `nil`, so a genuine (non-sentinel) DB fault on those paths was converted to `ErrInternal`
  with no server-side log line — now every internal fault is logged at the boundary. (Preceding
  contextual/leveled log lines were intentionally kept, since `sanitizeError` is silent on
  sentinels and those lines are the sole record of events like refresh-token reuse.)
- **De-duplicated the 16-column user row scan** into a single `scanUser` helper + `userColumns`
  constant, reused by all five user-loading paths, so a column add/reorder is one edit instead of
  five parallel ones.
- **De-duplicated the affected-rows check** into a `requireRowsAffected(result, notFound)` helper,
  replacing ~15 inline copies across the entity repositories.

## [0.10.0] - 2026-06-15

Security release closing a tenant-isolation gap, plus an API-ergonomics cleanup.
Several public signatures change; no schema migration is required.

### Security

- **The per-user self-service and building-block methods are now tenant-scoped.**
  A cluster of methods accepted a bare user id and reached repository queries that
  filtered on `id` only — so a caller acting for tenant B could, with another
  tenant's user UUID, read that user's password hash, drive it toward lockout,
  overwrite its activity timestamps, force-log-it-out, or (with the old password)
  change its password. Every such path now requires and enforces a tenant:
  - `AuthService.LogoutAll(ctx, userID, tenantID)` — bumps `token_version` scoped to
    the tenant first, so a cross-tenant id fails closed (`ErrNotFound`) before any
    refresh token is touched.
  - `AuthService.ChangePassword` — `model.ChangePasswordRequest` gains a required
    `TenantID`; the old-password read and the password write are both tenant-scoped.
  - `UserService.VerifyPassword`, `UpdateLastLogin`, `IncrementFailedLoginCount`, and
    `GetDisplayName` all take a `tenantID` and use tenant-scoped queries.
  - `UserService.GetByIDOnly` (which returned a full user record — including the
    password hash — by id alone) is **removed** from the public interface. The
    internal token-validation path that legitimately needs an id-only lookup is
    unaffected.

  A new integration test (`TestCrossTenantUserOperationsAreRejected`) exercises each
  path cross-tenant and asserts `ErrNotFound` with no side effect on the victim
  account, plus same-tenant positive controls.

### Changed (breaking)

- `AuthService.LogoutAll` now takes `(ctx, userID, tenantID)`.
- `model.ChangePasswordRequest` adds a required `TenantID` field.
- `UserService.VerifyPassword`, `UpdateLastLogin`, `IncrementFailedLoginCount`, and
  `GetDisplayName` each take a trailing `tenantID string`.
- `UserService.GetByIDOnly` is removed (use `GetByID(ctx, userID, tenantID)`).
- **`InvitationService.AcceptInvitation` now takes `model.AcceptInvitationRequest`**
  (`{Code, Email, DisplayName, PasswordHash}`) instead of four positional strings.
- **`OTPService.Generate` and `OTPService.Validate` now take request structs**
  (`model.OTPGenerateRequest{TenantID, Email, Purpose, ExpirationDuration}` and
  `model.OTPValidateRequest{TenantID, Email, Code, Purpose}`).

### Removed (internal — not part of the public API)

- The tenant-less repository mutators `SetPassword`, `VerifyPassword`,
  `IncrementTokenVersion`, `IncrementFailedLoginCount`, `UpdateLastLogin`, `Unlock`,
  and `GetDisplayName` were removed in favor of their `*ByTenant` variants, so the
  unscoped query can no longer be reintroduced by accident.

## [0.9.1] - 2026-06-15

Non-breaking correctness, robustness, dependency, and documentation polish from a
third review pass. No public API signatures change; no schema migration.

### Fixed

- **`APIKeyService.CreateAPIKey` now rejects a non-positive `ExpiresIn`.** A zero or
  negative duration previously minted a key with an `expires_at` in the past (dead on
  arrival); because `nil` means "never expires", a typo'd negative value was an easy
  way to get surprising behavior. It now returns a clear error, matching the
  positive-duration intent used elsewhere.
- **`maskValue` no longer over-reveals a secret when its first `_`/`-` delimiter sits
  late in the string.** The masked display form now reveals only a *short* leading
  type tag (e.g. `sk-`, `cur_`) plus the last 4 characters, and always keeps a masked
  gap between them; a delimiter far into the value is not treated as a type tag (which
  previously could echo most of the secret into logs/API responses). Cryptographic
  handling was never affected — the stored secret is encrypted and never exposed.

### Changed

- Dependency patch bumps: `golang-jwt/jwt/v5` `v5.3.0` → `v5.3.1`, `golang.org/x/crypto`
  `v0.52.0` → `v0.53.0` (transitively `golang.org/x/text` → `v0.38.0`,
  `golang.org/x/sync` → `v0.21.0`).

### Documentation

- `TenantService.UpdateSettings` now documents that the `map[string]any` is an open,
  application-defined bag the library does not interpret (values must be
  JSON-serializable).
- README clarifies that "comprehensive logging" applies only when a `Logger` is
  injected (logging is a no-op otherwise); the secret example marks its value as a
  placeholder to replace.

## [0.9.0] - 2026-06-15

API-ergonomics release addressing the breaking findings from the review. Several
public types and signatures change; no schema migration is required.

### Removed

- **`JWTConfig.RefreshSecret`** — it was required at construction but never used
  for anything (refresh tokens are opaque random strings, hashed with
  `RefreshTokenHMACSecret`, not signed). Delete it from your config; nothing else
  changes. The internal `NewJWTService` signature drops its unused `refreshSecret`
  parameter accordingly.
- The dead non-tenant repository mutators (`Update`/`Delete`/`Enable`/`Disable`/
  `Lock`) — every public path already used the tenant-scoped variants.

### Changed (breaking)

- **`InvitationService.CreateInvitation` now takes a `model.CreateInvitationRequest`**
  instead of seven positional parameters:
  `CreateInvitation(ctx, model.CreateInvitationRequest{TenantID, CreatedBy, Email, Roles, MaxUses, ExpiresIn})`.
  `MaxUses` (`*int`) and `ExpiresIn` (`*time.Duration`) are optional (default 1 use /
  7 days).
- **`model.UpdateUserRequest` fields are now pointers** (`DisplayName *string`,
  `Roles *[]string`): a nil field leaves that column unchanged, enabling partial
  updates. `token_version` is now bumped **only when roles change** — a
  display-name-only update no longer invalidates the user's sessions.
- **`model.Tenant.Settings` is now `map[string]any`** (was a raw JSON `string`),
  symmetric with `TenantService.UpdateSettings`, so a read-modify-write round-trip
  needs no manual JSON (un)marshaling.

### Changed (internal — not part of the public API)

- Moved the repository plumbing types `VerificationCode`,
  `CreateVerificationCodeRequest`, `OTPConsumeResult`, `RefreshToken`, and
  `CreateRefreshTokenRequest` out of the public `model` package into
  `internal/repository` (they were never consumer-facing). `model.GenerateResponse`
  and `model.SessionInfo` remain public.

## [0.8.1] - 2026-06-15

Hardening and fixes from a full multi-dimensional review. No public API signatures
change. Two behavior changes are noted under Fixed (both move toward the documented
contract).

### Security

- **The error-sanitization boundary now actually holds.** `sanitizeError` (which
  collapses non-sentinel errors to `ErrInternal` so driver/schema/SQL details never
  reach callers) was only applied to a handful of read methods. It is now applied
  across every public service method — `AuthService`, `OTPService`, `TokenService`,
  `TenantService`, and all `UserService`/`InvitationService` mutators — so a genuine
  DB fault no longer leaks raw pgx/constraint text. Sentinel errors (`ErrInvalidOTP`,
  `ErrInvalidCredentials`, `ErrNotFound`, …) still pass through unchanged, so
  `errors.Is` matching is unaffected.
- **CI actions are pinned to commit SHAs.** The gosec job used `securego/gosec@master`
  and `actions/checkout@v4` (mutable refs); both are now pinned to full SHAs, matching
  the govulncheck job.

### Fixed

- **`Logout` / `RevokeRefreshToken` are now idempotent** — revoking an unknown or
  already-revoked refresh token returns `nil` (success) instead of an error.
- **README "Expiration Duration" section** no longer documents the removed
  `"30d"`/`"6M"`/`"1y"` string format; it now shows `*time.Duration` (matching v0.8.0).
- `SaveSecret` scans the nullable `masked_key` column via `sql.NullString` (consistent
  with `ListSecrets`).
- `SECURITY.md` supported-versions table updated to `0.8.x`; `CHANGELOG` 0.7.0 timestamp
  types clarified.

### Changed (internal)

- Removed the unused `Lock` method from the internal `authRepository` interface.
- `validateDomain` compiles its regexp once at package load instead of per call;
  invitation email normalization reuses the shared `normalizeEmail` helper; a couple
  of stale doc comments corrected.

## [0.8.0] - 2026-06-15

Small follow-up: `CreateAPIKeyRequest.ExpiresIn` becomes a real `time.Duration`,
and the PostgreSQL driver is updated.

### Changed (breaking)

- **`CreateAPIKeyRequest.ExpiresIn` is now `*time.Duration`** (was `*string` with a
  `"30d"`/`"6M"`/`"1y"` shorthand). The shorthand never carried calendar semantics
  — it was collapsed internally to a fixed duration with 30-day months and 365-day
  years and applied as `time.Now().Add(d)` — so nothing is lost: pass a
  `time.Duration` directly. This matches `InvitationService.CreateInvitation`'s
  `expiresIn *time.Duration` and removes the non-standard `parseExpiration` parser.

  ```go
  // before: ExpiresIn: ptr("90d")
  d := 90 * 24 * time.Hour
  // after:  ExpiresIn: &d
  ```

### Changed

- **Bumped `github.com/jackc/pgx/v5` to v5.9.2** (from v5.8.0).

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
- **Response timestamps are `time.Time`.** `CreateAPIKeyResponse.CreatedAt`,
  `SaveSecretResponse.CreatedAt`, and `SaveSecretResponse.UpdatedAt` are now
  `time.Time`, and `CreateAPIKeyResponse.ExpiresAt` is `*time.Time` (all were
  pre-formatted RFC3339 strings); `SaveSecretResponse.CreatedBy` is now `uuid.UUID`.
  Callers can do time math without re-parsing; JSON output is unchanged.

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

[Unreleased]: https://github.com/modgudinc/authkit-go/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/modgudinc/authkit-go/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/modgudinc/authkit-go/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/modgudinc/authkit-go/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/modgudinc/authkit-go/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/modgudinc/authkit-go/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/modgudinc/authkit-go/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/modgudinc/authkit-go/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/modgudinc/authkit-go/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/modgudinc/authkit-go/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/modgudinc/authkit-go/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/modgudinc/authkit-go/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/modgudinc/authkit-go/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/modgudinc/authkit-go/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/modgudinc/authkit-go/releases/tag/v0.1.0
