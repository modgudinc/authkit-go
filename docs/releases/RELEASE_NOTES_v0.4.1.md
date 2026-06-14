# authkit-go v0.4.1

A bug-fix and hardening release on top of [v0.4.0](RELEASE_NOTES_v0.4.0.md). **No
public API or behavior changes** for correctly-configured callers — drop-in
upgrade. One new, safe database migration is included.

```bash
go get github.com/modgudinc/authkit-go@v0.4.1
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## Security

- **Secret encryption is context-bound.** AES-256-GCM ciphertext is now
  authenticated against its `(tenant_id, key)` via the GCM additional
  authenticated data, so a secret relocated to another row (e.g. by DB tampering
  under the shared encryption key) fails authentication instead of decrypting as
  another tenant's value. **Backward-compatible:** ciphertext written before this
  release still decrypts (new writes carry a `v1:` marker) — no re-encryption
  migration required.
- **OTP rate limit is enforced atomically** inside the upsert, closing a
  check-then-write TOCTOU where two concurrent requests could each issue a code.
- **`ChangePassword` reads the current hash from the primary** (not a replica),
  removing a read-after-write window in the old-password auth gate.
- **Short secrets are fully masked** (`maskValue` floor raised 8 → 12 chars).
- **Background "last used" updates are concurrency-bounded** (max 64 in flight),
  so a burst of validations can't fan out unbounded goroutines on the write pool.

## Fixed

- **Expired refresh tokens are no longer mis-flagged as reuse/theft.** An
  expired-but-never-consumed token is no longer marked revoked, so re-presenting
  it reports "expired" rather than triggering family-wide reuse revocation
  (reserved for genuinely consumed/rotated tokens).
- **`New()` rejects an out-of-range bcrypt cost** (outside 4–31) instead of
  silently coercing it. *(If you pass an explicit cost, ensure it is 0 — use
  default — or within 4–31.)*
- **`UserService.List` clamps `limit`/`offset`** (default 50, max 1000, offset ≥ 0).
- **Secret service write/list/count errors are sanitized** to `ErrInternal`, like
  the read paths, so DB faults don't leak driver text.
- **`CreateTenant` / `SetAllowedDomains` reject an empty `allowed_domains` list**
  with a clear error instead of a raw constraint violation.
- Doc/comment fixes (README `ValidateAPIKey` example no longer shadows `context`;
  `GenerateRefreshToken` godoc corrected to HMAC-SHA256).

## Added

- **Migration `000003_drop_redundant_api_key_hash_index`** — drops the redundant
  `idx_api_keys_key_hash` (the column is already `UNIQUE`-indexed). Safe and
  backward-compatible.
- Regression tests: INET `ip_address` round-trip, `api_keys` UUID `key_id`
  round-trip + 000003 index state, OTP atomic rate-limit, and AES-GCM AAD
  (wrong-context rejection, legacy-ciphertext decryption).

## Documentation

- The README "Error Handling" section and the `patterns.md` JWT middleware now
  document the sentinel-error contract: branch with `errors.Is`, and map account
  states to **403** and `ErrInternal`/unexpected errors to **500** — not a blanket
  401.

## Upgrading from 0.4.0

1. **Run migration `000003_drop_redundant_api_key_hash_index`** (drops one
   redundant index; no data change).
2. No code changes required. If you pass an explicit `PasswordConfig.BcryptCost`,
   confirm it is `0` (default) or within bcrypt's 4–31 range — an out-of-range
   value is now rejected at `New()` instead of silently defaulted.

## Verification

`gofmt`, `go vet` (default + `integration`), `golangci-lint`, and `gosec` are
clean; unit and PostgreSQL integration tests pass (including the new regression
tests listed above), with coverage enforced at ≥ 30% in CI.

---

Full changes: see [CHANGELOG.md](../../CHANGELOG.md). Licensed under [Apache-2.0](../../LICENSE).
