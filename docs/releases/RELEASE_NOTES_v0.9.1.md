# authkit-go v0.9.1

A non-breaking polish release from a third review pass: two robustness fixes, patch
dependency bumps, and documentation clarifications. No public API signatures change,
and no schema migration is required.

```bash
go get github.com/modgudinc/authkit-go@v0.9.1
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## Fixed

### `CreateAPIKey` rejects a non-positive `ExpiresIn`

A zero or negative `ExpiresIn` previously produced a key whose `expires_at` was already
in the past — dead on arrival — with no error. And since `nil` means "never expires", a
mistyped negative value was an easy footgun. `CreateAPIKey` now returns a clear error
for any non-positive duration.

### `maskValue` no longer over-reveals secrets with a late delimiter

The masked form shown in audit output / API responses (`sk-************f456`) is built
from a short leading type tag plus the last 4 characters. For a value whose first
`_`/`-` delimiter sat late in the string, the old logic could echo most of the secret
into the "prefix". The masker now:

- reveals only a **short** leading type tag (delimiter within the first few chars),
- always keeps a masked gap between the revealed tag and the revealed suffix, and
- falls back to suffix-only masking when there is no early type tag.

This is a display-hardening fix only — stored secrets are AES-256-GCM encrypted and the
plaintext is never exposed by masking.

## Changed

- Dependency patch bumps (no API impact), verified against the unit and PostgreSQL
  integration suites:
  - `github.com/golang-jwt/jwt/v5` `v5.3.0` → `v5.3.1`
  - `golang.org/x/crypto` `v0.52.0` → `v0.53.0`
  - (transitive) `golang.org/x/text` → `v0.38.0`, `golang.org/x/sync` → `v0.21.0`

## Documentation

- `TenantService.UpdateSettings` documents that its `map[string]any` is an open,
  application-defined bag the library does not interpret (values must be
  JSON-serializable; it is returned verbatim as `Tenant.Settings`).
- README notes that logging is active only when a `Logger` is injected; the secret
  example marks its value as a placeholder.

## Verification

`gofmt`, `go vet` (default + `integration`), and `golangci-lint` are clean; unit and
PostgreSQL integration tests pass, including a new `maskValue` regression case for a
late delimiter.

---

Full changes: see [CHANGELOG.md](../../CHANGELOG.md). Licensed under [Apache-2.0](../../LICENSE).
