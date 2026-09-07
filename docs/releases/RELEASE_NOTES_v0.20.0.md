# authkit-go v0.20.0

The **decoupled-identity** release of **authkit-go** — a Go identity and authentication library backed by PostgreSQL. It gives you global user identities, `user ↔ tenant` memberships, JWT access tokens with rotating refresh tokens, API keys, OTP verification, invitations, and encrypted provider secrets — and leaves HTTP routing, authorization policy, and delivery (email/SMS) to your application.

```bash
go get github.com/modgudinc/authkit-go@v0.20.0
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

> **Large breaking change.** `v0.20.0` is a substantial, breaking rework of authkit's identity model within the pre-1.0 (`0.x`) line. Because authkit had no production identity data, the `000001` schema was edited in place — there is **no data migration**.

## The model: global identities + tenant memberships

A **user is a global identity** — a globally-unique, case-insensitive email plus a password, with **no** tenant and **no** roles. A **membership** is a `(user, tenant)` row that grants the identity access to one workspace with a set of **opaque role strings**: authkit stores them but never interprets them — **authkit owns the membership graph; your application owns the role policy.**

A login authenticates the identity and opens one refresh-token **identity session** shared across the user's workspaces; from it you mint **workspace-scoped access tokens** (each scoped to one active membership's tenant + roles). Switching workspace mints a new token from the same session — no re-login. This mirrors WorkOS / Auth0 Organizations / Stytch B2B.

## Highlights

- **Global identities + memberships** — `UserService` manages global users; the new `MembershipService` manages the `user ↔ tenant` graph (grant/revoke, roles, member and workspace lists). One person can belong to many workspaces with a single account and password.
- **Workspace-scoped tokens with dual versioning** — access-token JWTs carry both an identity `token_version` and a per-membership `membership_token_version`. A credential event (password change, disable, logout-all) invalidates **every** workspace's tokens; a role change or membership revoke invalidates **only that workspace's** tokens.
- **Flexible login** — `Login(email, password, tenantID)` for a known workspace, `LoginByEmail` when it isn't (returns the user's memberships to choose from), and `MintWorkspaceToken` to select/switch workspace from an existing session.
- **JWT + rotating refresh tokens** — short-lived HS256 access tokens plus single-use refresh tokens stored as HMAC-SHA256 hashes, with **refresh-token reuse/theft detection** (a replayed token revokes the whole family and bumps the identity token version).
- **Invitations that reuse identities** — `Accept` redeems atomically and reuses the invitee's existing global identity (or creates one), then grants the invited membership — invited users don't get a second account/password.
- **API keys** — `sk_live_`-prefixed keys, stored only as HMAC hashes, tenant-scoped, with expiry and revocation.
- **OTP verification** — 6-digit, `crypto/rand`-generated codes keyed by `(email, purpose)`, with a per-code failed-attempt lockout and constant-time comparison.
- **Encrypted secrets** — provider API keys stored with AES-256-GCM (authenticated, random nonce per write).
- **Ergonomics** — single `New(Config)` constructor with fail-fast validation; injectable `logger.Logger`, `metrics.Metrics`, and `ratelimit.RateLimiter`; context-first methods; exported sentinel errors (`authkit.Err*`) for `errors.Is`.

## Breaking changes

- `users` is a **global** identity: `tenant_id` and `roles` are removed; email is globally unique (`UNIQUE (lower(email))`). `User`, `CreateUserRequest`, `UpdateUserRequest`, `JWTClaims` (now carries `membership_token_version`), and `LoginResponse` (now carries `Memberships`) change accordingly.
- `UserService` is identity-level (keyed by user id / email). `Count` and `UpdateRoles` are **removed** — roles move to `MembershipService.UpdateRoles`, member counts to `MembershipService.CountByTenant`.
- `AuthService.Login` now requires an active membership in `TenantID`; `RefreshToken` takes the target `TenantID`; `LogoutAll(userID)` and `ChangePassword` are identity-level (no tenant); `ValidateJWT` checks the identity **and** membership token version plus membership status.
- OTP is keyed by `(email, purpose)` — tenant dropped from `OTPGenerateRequest` / `OTPValidateRequest` and `OTPService.Delete`.
- `InvitationService.Accept` returns `(userID, created, error)`.

## Security

- **Decoupled invalidation** — `ValidateJWT` rejects on either an identity or a membership `token_version` mismatch, a suspended/removed membership (`ErrTokenRevoked`), or a disabled/locked account; the revocation/account-status reads use the primary so writes are observed without replica lag.
- **No account enumeration** — unknown email, disabled, and locked accounts all return a single generic `ErrInvalidCredentials` with a dummy bcrypt comparison to equalize timing. A valid login for a workspace the user is not a member of returns `ErrNoActiveMembership` (an authorization, not authentication, outcome) and never revokes the identity session.
- **Refresh-token rotation is atomic**; reuse of a consumed token revokes the whole family (`ErrRefreshTokenReuse`) and bumps the identity token version.
- **OTP brute force is bounded** by a per-code attempt lockout, not just generation rate limiting; codes are stored only as a keyed HMAC-SHA256.
- Passwords are hashed with bcrypt (cost 12 by default); JWT/HMAC secrets must be ≥ 32 bytes.
- JWT validation pins `HS256` (blocks `alg:none` / algorithm-confusion), requires an `exp` claim, and allows a small clock-skew leeway; optional `iss`/`aud` enforcement.

See [SECURITY.md](SECURITY.md) for the disclosure policy, secret-management expectations, and rotation guidance.

## Requirements

- Go **1.25+**
- PostgreSQL — apply `migrations/000001_identity_schema.up.sql` (copy and replace the `authkit` schema name if you use a custom schema).
- Two `*sql.DB` handles (read-write and read-only; they may be the same), opened with the pgx driver (`_ "github.com/jackc/pgx/v5/stdlib"`).

## Getting started

See the [README](README.md) for setup and per-service examples, and [docs/](docs/) for architecture, patterns, and troubleshooting.

## Documentation

- [Architecture, data model & security assumptions](docs/architecture.md)
- [Service examples](docs/examples.md)
- [Common patterns](docs/patterns.md)
- [Troubleshooting](docs/troubleshooting.md)

---

Licensed under [Apache-2.0](LICENSE).
