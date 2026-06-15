# authkit-go v0.8.1

A hardening + fixes release from a full multi-dimensional review (security,
ergonomics, code smells, docs, supply-chain). No public API signatures change.

```bash
go get github.com/modgudinc/authkit-go@v0.8.1
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## Security

- **The documented error-sanitization boundary now actually holds.** `sanitizeError`
  collapses any non-sentinel (genuine DB/driver) error to `ErrInternal` so
  schema/constraint/driver text never reaches a consumer that renders `err.Error()`.
  It had only been wired into a handful of read methods; it is now applied across
  **every** public service method — all of `AuthService`, `OTPService`,
  `TokenService`, `TenantService`, and the `UserService`/`InvitationService`
  mutators. Sentinel errors still pass through unchanged, so `errors.Is(err, …)`
  matching is unaffected.
- **CI is pinned to commit SHAs.** The gosec job ran `securego/gosec@master` and
  `actions/checkout@v4` (mutable refs, a supply-chain hole); both are now pinned to
  full SHAs like the govulncheck job already was.

## Fixed

- **`Logout` is idempotent.** Revoking an unknown or already-revoked refresh token
  now returns `nil` (success) instead of an error — calling logout twice, or after a
  token already rotated away, no longer errors.
- **README "Expiration Duration"** no longer shows the removed `"30d"`/`"6M"`/`"1y"`
  string format (a v0.8.0 doc miss); it now documents `*time.Duration`.
- `SaveSecret` reads the nullable `masked_key` column with `sql.NullString`, matching
  `ListSecrets`.
- `SECURITY.md` supported-versions table refreshed to `0.8.x`; a CHANGELOG timestamp
  description and two stale code comments corrected.

## Internal

- Dropped the unused `Lock` method from the internal `authRepository` interface.
- `validateDomain` compiles its regexp once at package load; invitation email
  normalization reuses the shared `normalizeEmail`.

## Behavior-change notes

Two changes alter observable behavior, both toward the documented contract:
1. On a genuine storage fault, public methods now return `ErrInternal` (sanitized)
   rather than a raw wrapped driver error. If you matched those raw strings, switch
   to `errors.Is(err, authkit.ErrInternal)`.
2. `Logout` returns `nil` for an unknown/already-revoked token. If you relied on it
   erroring, branch on the token's existence yourself beforehand.

## Verification

`gofmt`, `go vet` (default + `integration`), and `golangci-lint` are clean; unit and
PostgreSQL integration tests pass.

---

Full changes: see [CHANGELOG.md](../../CHANGELOG.md). Licensed under [Apache-2.0](../../LICENSE).
