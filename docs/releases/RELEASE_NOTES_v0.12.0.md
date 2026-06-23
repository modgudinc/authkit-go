# authkit-go v0.12.0

Production-readiness hardening from a multi-dimension security/operations audit. It
closes the medium-severity policy and observability gaps and a high-severity
documentation defect. This release contains **breaking changes** — a new
required-when-used config secret, a schema change, and two new `UserService` interface
methods — so per the pre-1.0 policy it is a minor bump.

```bash
go get github.com/modgudinc/authkit-go@v0.12.0
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## Why this release

A production-readiness audit found no blockers — multi-tenant isolation, the JWT
lifecycle, password/lockout, and refresh-token reuse detection were already sound — but
flagged a set of medium-severity gaps that are worth closing before GA: OTP codes stored
in plaintext, reuse detection not cutting off already-issued access tokens, an
incomplete account-freeze in `ChangePassword`, an unbounded write-only audit table, and
no metrics seam for alerting. It also caught a high-severity doc defect (the README
demonstrated a removed, tenant-unsafe method). This release fixes all of them.

## Breaking changes

### `OTPConfig.HMACSecret` is now required when `OTPService` is used

OTP codes are no longer stored in plaintext — they are stored only as a keyed
HMAC-SHA256, mirroring refresh tokens and API keys. Configure a dedicated secret:

```go
OTPConfig: authkit.OTPConfig{
    HMACSecret: os.Getenv("OTP_HMAC_SECRET"), // ≥ 32 bytes of CSPRNG output
},
```

It is validated for length at construction when set; `OTPService.Generate`/`Validate`
return the new `ErrOTPSecretMissing` sentinel when it is absent. Services other than OTP
are unaffected if you omit it.

### Schema change — re-apply migration `000001`

- `verification_codes.code` → `code_hash VARCHAR(64)` (stores the HMAC, never plaintext).
- The unused `idx_user_status_changes_changed_by` index is dropped.

Both edits are in the consolidated `000001` migration. A fresh `migrate up` gets the
corrected schema. Any existing OTP rows are ephemeral (short TTL, single-use) and need
no data migration.

### `UserService` interface gains two methods

```go
StatusHistory(ctx, userID, tenantID) ([]*model.UserStatusChange, error)
CleanupStatusChanges(ctx, olderThan time.Duration) (int64, error)
```

Code that implements or mocks `authkit.UserService` must add these.

## Security & correctness

- **OTP codes are stored as a keyed HMAC-SHA256, never in plaintext.** A read-only
  database/backup/replica disclosure no longer yields usable second factors. Validation
  hashes the supplied code and compares in constant time.
- **Refresh-token reuse now invalidates outstanding access tokens.** On detected
  reuse/theft, the rotation transaction bumps the user's `token_version` (in addition to
  revoking the whole token family), so `ValidateJWT` rejects every already-issued access
  token immediately instead of letting it live to its `exp`.
- **`ChangePassword` gates on account status.** A disabled or locked account can no longer
  rotate its own password mid-freeze (returns `ErrAccountDisabled`/`ErrAccountLocked`),
  matching the `Login` and `ValidateJWT` gates. The gate runs before old-password
  verification.

## Added

- **Optional metrics seam (`metrics` package + `Config.Metrics`).** A minimal,
  no-op-by-default `Metrics` interface called at key decision points — login
  success/failure, account lockout, OTP failure/lockout, and refresh-token reuse.
  Canonical counter names are exported as `metrics.Counter*`. Unlike the logger, these
  survive independently of log level, so they are the recommended basis for alerting.
- **`UserService.StatusHistory`** reads a user's status-change audit trail
  (tenant-scoped), and **`UserService.CleanupStatusChanges`** prunes it by age. The
  `user_status_changes` table previously had no read API and no retention method.
- **Distinguishable refresh-reuse event.** Reuse/theft is logged as a dedicated elevated
  event (`event=refresh_token_reuse`, carrying user/family ids via the new
  `model.RefreshTokenReuseError`) and metered, instead of a generic warning.
- **`ErrOTPSecretMissing`** sentinel.

## Fixed

- **README demonstrated `tokenService.RevokeAllUserTokens`** — a method intentionally
  removed from the public `TokenService` because it scoped by `user_id` with no tenant
  check. Replaced with the tenant-safe `authService.LogoutAll`.
- **The integration CI job now runs with `-race`**, covering the detached `last_used`
  fan-out (the only concurrent goroutine in non-test source, exercised only by the
  integration suite).
- Doc drift: the `model` package overview named a non-existent `RefreshToken` type and
  the pre-0.11 `GetTenant` method; the README sentinel list omitted `ErrValueTooLong`.

## Documentation

- Documented that several security signals (OTP lockout, refresh-token reuse,
  sub-threshold failed logins) are **logger-only** and lost if no `Logger`/`Metrics` is
  injected (account lock/disable/enable transitions are persisted to
  `user_status_changes` regardless).
- Documented required connection-pool limits and server-side
  `statement_timeout`/`lock_timeout` as caller-owned controls (README + SECURITY.md),
  moved pool configuration into the primary quickstart, and added OTP-storage,
  OTP-secret, and metrics guidance.
- Replaced the drift-prone supported-versions table in SECURITY.md with a "latest minor
  only" policy statement.

## Upgrading

1. **If you use `OTPService`,** set `OTPConfig.HMACSecret` (≥ 32 bytes of CSPRNG output;
   `openssl rand -base64 32`). Without it, `Generate`/`Validate` return
   `ErrOTPSecretMissing`.
2. **Re-apply migration `000001`** to pick up `verification_codes.code_hash` and the
   dropped index.
3. **If you implement or mock `authkit.UserService`,** add `StatusHistory` and
   `CleanupStatusChanges`.
4. **Recommended for production:** inject `Config.Metrics`, schedule
   `UserService.CleanupStatusChanges` per your retention policy, bound the `*sql.DB`
   pools, and set a server-side `statement_timeout`/`lock_timeout` (see the README
   "Performance Considerations").

## Verification

`gofmt`, `go vet` (default + `integration`), and `golangci-lint` (default +
`integration`) are clean; the unit suite (including the race detector and new tests for
the `ChangePassword` status gate and the OTP-secret requirement) and the PostgreSQL
integration suite pass.

---

Full changes: see [CHANGELOG.md](../../CHANGELOG.md). Licensed under [Apache-2.0](../../LICENSE).
