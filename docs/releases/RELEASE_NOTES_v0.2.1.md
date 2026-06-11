# authkit-go v0.2.1

A small security-hardening and documentation patch on top of [v0.2.0](RELEASE_NOTES_v0.2.0.md). **No breaking changes** — drop-in upgrade.

```bash
go get github.com/modgudinc/authkit-go@v0.2.1
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## Security

- **`UserService.DisableByTenant` now revokes the user's refresh tokens**, matching `Disable` (which is now a thin alias for it). Previously `DisableByTenant` only flipped `is_enabled`/`token_version`, leaving refresh-token rows in place — so an account that was disabled and later re-enabled within the refresh-token TTL could resurrect pre-disable sessions. Both disable entry points now terminate sessions consistently.

## Documentation

- Documented that `CreateInvitation` / `AcceptInvitation` do **not** enforce the tenant's `allowed_domains` — this is intentional (admins legitimately invite out-of-domain users such as contractors). If you require invited emails to stay within the tenant's domain list, call `TenantService.ValidateDomainAccess` before creating the invitation; the README invitation flow example now shows this optional gate.
- Updated `docs/patterns.md` to recommend the atomic `AcceptInvitation` for invitation signup instead of the manual `ValidateInvitation` → create-user → `IncrementUseCount` sequence (which is non-atomic and can over-redeem a single-use invitation). README and `docs/examples.md` already used `AcceptInvitation`; this brings `patterns.md` in line.

## Upgrading from 0.2.0

- Drop-in; no API signatures changed.
- **One behavior change to note:** `DisableByTenant` now also deletes the user's refresh tokens. This is the safer behavior and matches `Disable`. If you previously relied on disabled users being able to resume sessions after re-enable, that no longer happens — re-enabled accounts must obtain new tokens (e.g. by logging in again).

## Verification

`gofmt`, `go vet` (default + `integration`), `golangci-lint`, and `gosec` are clean; unit and PostgreSQL integration tests pass (including a new test asserting `DisableByTenant` revokes refresh tokens), with coverage enforced at ≥ 30% in CI.

---

Full changes: see [CHANGELOG.md](../../CHANGELOG.md). Licensed under [Apache-2.0](../../LICENSE).
