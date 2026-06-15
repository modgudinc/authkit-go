# authkit-go v0.8.0

A small follow-up to v0.7.0: API-key expiry is now a real `time.Duration`, and the
PostgreSQL driver is updated.

```bash
go get github.com/modgudinc/authkit-go@v0.8.0
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## Breaking changes

- **`CreateAPIKeyRequest.ExpiresIn` is now `*time.Duration`** (was `*string`).

  The old `"30d"` / `"6M"` / `"1y"` shorthand never had calendar semantics — it was
  collapsed internally to a fixed duration (30-day months, 365-day years) and
  applied as `time.Now().Add(d)`. So the `time.Duration` form loses nothing and is
  more honest; it also matches `InvitationService.CreateInvitation`, which already
  takes `expiresIn *time.Duration`.

  ```go
  // before
  ExpiresIn: ptr("90d")
  // after
  d := 90 * 24 * time.Hour
  ExpiresIn: &d
  ```

  `nil` still means "never expires". The non-standard `parseExpiration` parser (and
  its `M`-vs-`m` / `len<2` foot-guns) is gone.

## Changed

- **`github.com/jackc/pgx/v5` bumped to v5.9.2** (from v5.8.0).

## Upgrading

Replace the `ExpiresIn` shorthand string with a `time.Duration`:
`"30d"` → `30*24*time.Hour`, `"6M"` → `6*30*24*time.Hour`, `"1y"` →
`365*24*time.Hour` (the same fixed durations the shorthand produced).

## Verification

`gofmt`, `go vet` (default + `integration`), and `golangci-lint` are clean; unit
and PostgreSQL integration tests pass, with new service-level coverage for
`CreateAPIKey` (a `*time.Duration` produces `ExpiresAt ≈ now+duration`; `nil`
produces a never-expiring key).

---

Full changes: see [CHANGELOG.md](../../CHANGELOG.md). Licensed under [Apache-2.0](../../LICENSE).
