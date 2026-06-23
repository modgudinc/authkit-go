# authkit-go v0.13.0

Operational hardening and observability work: a pluggable rate-limiter seam,
context-aware logging, health checks, schema/index cleanup, and the remaining
production-readiness follow-ups. It contains one **breaking change** — the
`logger.Logger` interface is now context-first — so per the pre-1.0 policy it is a
minor bump.

```bash
go get github.com/modgudinc/authkit-go@v0.13.0
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## Why this release

v0.12.0 closed the production-readiness blockers/high/medium gaps; this release lands
the lower-priority follow-ups from the same audit — the things that make the library
nicer to *operate*: a place to plug in rate limiting, log lines that can carry your
request/trace IDs, readiness probes, observability counters, and a leaner index set.

## Breaking changes

### `logger.Logger` is now context-first

Each method takes the call's `context.Context` as its first argument, so an
implementation can attach request/trace/correlation IDs from the context onto every
line (exactly as `log/slog`'s `*Context` methods do):

```go
type Logger interface {
    Debug(ctx context.Context, msg string, fields ...interface{})
    Info(ctx context.Context, msg string, fields ...interface{})
    Warn(ctx context.Context, msg string, fields ...interface{})
    Error(ctx context.Context, msg string, fields ...interface{})
}
```

Update any `Logger` implementation to add the `ctx` parameter to its four methods —
a `log/slog` adapter becomes a one-liner per method (`s.l.InfoContext(ctx, msg, fields...)`).
The library passes the operation's context where it has one and `context.Background()`
from the pure-CPU services (password, JWT) that do no I/O.

### Schema change — re-apply migration `000001`

Index cleanup (still consolidated in `000001`; a fresh `migrate up` gets the final
schema):

- Dropped ten verified-unused indexes (boolean/`locked_until` user columns, redundant
  `tenant_id`/`provider` indexes already covered by primary keys, and the
  refresh-token session-metadata indexes).
- Replaced the separate `(tenant_id)` + `(created_at)` index pairs on
  users/api_keys/invitations with composite `(tenant_id, created_at DESC)` indexes for
  the list endpoints.
- Added a functional `UNIQUE (tenant_id, lower(email))` on users — case-insensitive
  defense-in-depth so a writer bypassing the Go-side normalization cannot create
  case-variant duplicate accounts.

## Added

- **Pluggable rate-limiter** — `ratelimit.RateLimiter` (aliased `authkit.RateLimiter`)
  + `Config.RateLimiter`, consulted by `Login`, `RefreshToken`, and
  `OTPService.Generate` with a documented key convention. A rejection returns the new
  `ErrRateLimited` sentinel (HTTP 429); a limiter error fails open (logged + metered).
  This is the recommended home for the IP/global rate limiting the library does not do
  itself.
- **Health checks** — `AuthKit.Ping(ctx)` pings both DB handles for readiness/liveness
  probes, and `Config.VerifyConnectivity` makes `New` fail fast on an unreachable
  database instead of deferring to the first query.
- **Observability counters** — `authkit_rate_limited_total`,
  `authkit_rate_limiter_error_total`, and `authkit_best_effort_write_failure_total`
  (the last surfaces swallowed last-login/reset/auto-unlock write failures, so a
  degraded primary is observable even while logins still succeed).
- **`ErrInvalidInput`** sentinel (HTTP 400), returned by `TenantService.UpdateSettings`
  when the settings map cannot be serialized to JSON.

## Changed

- `New` warns (does not reject) when `PasswordConfig.BcryptCost` exceeds
  `HighBcryptCostThreshold` (15) — a very high cost is a self-inflicted DoS since every
  login runs at least one bcrypt comparison.
- Demoted the per-request success log lines (`ValidateJWT` success, the per-attempt
  `Login` line) from Info to Debug.
- The compensating revocations in `RefreshTokenPair` (family-revoke for an inactive
  account, rotated-token cleanup on an access-token error) now run on a context
  detached from the request's cancellation, so a client disconnect cannot leave them
  half-applied.

## Fixed

- `SecretService.Get` no longer surfaces the raw decrypt/crypto error across the public
  API boundary; a decrypt/authentication failure maps to `ErrInternal` (a server-side
  integrity fault, not caller input).
- Corrected the `clockSkewLeeway` doc comment: the leeway applies to `exp` only — `iat`
  is informational and not validated, and `nbf` is never issued.

## Tests / CI

- Added unit tests for the bounded `last_used` fan-out (`runBoundedLastUsedUpdate`,
  driven concurrently so the unit job's `-race` covers the shared semaphore and the
  detached-goroutine lifecycle), `isUserLocked`, `hashToken`, and the rate-limiter
  wiring (rejection, key format, fail-open).
- Raised the integration coverage floor from 30% to 50% (actual ~55%) and added a 20%
  floor to the unit job. Both the unit and integration jobs run under `-race`.
- The `gosec` SARIF is now uploaded to GitHub code scanning (Security tab), not just as
  a build artifact.

## Documentation

- New README **Environment variables**, **Rate Limiting**, and **Health Checks**
  (incl. behavior-under-database-outage) sections.
- Documented that the library does not (and in idiomatic Go cannot reliably) zeroize
  secret material in memory, with OS/deployment mitigations (SECURITY.md).
- Documented on the `InvitationService` interface that the by-code operations are
  bearer-capability-based and not additionally tenant-checked (resolve via `Get` and
  check `TenantID` first if your model requires it).

## Upgrading

1. **Update your `Logger` implementation** to add `ctx context.Context` as the first
   parameter of `Debug`/`Info`/`Warn`/`Error`. (No-op if you pass `nil` or
   `logger.NopLogger{}`.)
2. **Re-apply migration `000001`** to pick up the index changes.
3. Optional but recommended for production: set `Config.RateLimiter`, `Config.Metrics`,
   and `Config.VerifyConnectivity`; wire `AuthKit.Ping` into a readiness probe.
4. New matchable sentinels available: `ErrRateLimited` (429) and `ErrInvalidInput` (400).

## Verification

`gofmt`, `go vet` (default + `integration`), and `golangci-lint` (default +
`integration`) are clean; standalone `gosec` passes; the unit and PostgreSQL
integration suites (both under `-race`, the latter exercising the re-applied migration
and new indexes) pass.

---

Full changes: see [CHANGELOG.md](../../CHANGELOG.md). Licensed under [Apache-2.0](../../LICENSE).
