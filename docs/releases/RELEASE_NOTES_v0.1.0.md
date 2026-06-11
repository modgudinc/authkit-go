# authkit-go v0.1.0

First public release of **authkit-go** — a multi-tenant identity and authentication library for Go, backed by PostgreSQL.

It gives you the building blocks for auth — users, tenants, JWT access tokens with rotating refresh tokens, API keys, OTP verification, invitations, and encrypted provider secrets — and leaves HTTP routing, authorization policy, and delivery (email/SMS) to your application.

```bash
go get github.com/modgudinc/authkit-go@v0.1.0
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## Highlights

- **Multi-tenant by design** — users, API keys, invitations, OTPs, and secrets are tenant-scoped; lookups and mutations are constrained to the owning tenant to prevent cross-tenant access (IDOR).
- **JWT + rotating refresh tokens** — short-lived HS256 access tokens plus single-use refresh tokens stored as HMAC-SHA256 hashes, with **refresh-token reuse/theft detection** (a replayed token revokes the whole token family).
- **API keys** — `sk_live_`-prefixed keys, stored only as HMAC hashes, with expiry and tenant-scoped validation/revocation.
- **OTP verification** — 6-digit, `crypto/rand`-generated codes, scoped to `(tenant, email, purpose)`, with a per-code failed-attempt lockout and constant-time comparison.
- **Invitations** — atomic `AcceptInvitation` that validates, consumes, and creates the user in one transaction, bound to the invitation's email and roles.
- **Encrypted secrets** — provider API keys stored with AES-256-GCM (authenticated, random nonce per write).
- **Ergonomics** — single `New(Config)` constructor with fail-fast validation, an injectable `logger.Logger` (and `logger.NopLogger`), context-first methods, and exported sentinel errors (`authkit.Err*`) for `errors.Is`.

## Security

- Tenant isolation on all per-tenant reads/writes (users, API keys, invitations, OTPs, secrets).
- Refresh-token rotation is atomic; reuse of a consumed token revokes the family (`ErrRefreshTokenReuse`).
- OTP brute force is bounded by a per-code attempt lockout, not just generation rate limiting.
- Login does not leak account existence/state: unknown, disabled, and locked accounts all return a single generic `ErrInvalidCredentials`, with a dummy bcrypt comparison to equalize timing (no username enumeration).
- Passwords hashed with bcrypt (cost 12 by default); JWT/HMAC secrets must be ≥ 32 bytes.
- JWT validation pins `HS256` (blocks `alg:none` / algorithm-confusion), requires an `exp` claim, and allows a small clock-skew leeway; optional `iss`/`aud` enforcement.
- Disabling, locking, or bumping a user's token version revokes their refresh tokens.

See [SECURITY.md](SECURITY.md) for the disclosure policy, secret-management expectations, and rotation guidance.

## Requirements

- Go **1.24+**
- PostgreSQL — apply `migrations/000001_identity_schema.up.sql` (copy and replace the `authkit` schema name if you use a custom schema).
- Two `*sql.DB` handles (read-write and read-only; they may be the same), plus the `github.com/lib/pq` driver.

## Getting started

See the [README](README.md) for setup and per-service examples, and [docs/](docs/) for architecture, patterns, and troubleshooting.

## Documentation

- [Architecture, data model & security assumptions](docs/architecture.md)
- [Service examples](docs/examples.md)
- [Common patterns](docs/patterns.md)
- [Troubleshooting](docs/troubleshooting.md)

---

Licensed under [Apache-2.0](LICENSE).
