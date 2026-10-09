# Architecture

`authkit-go` is a Go library for identity primitives built on a **decoupled** model: a user is a global identity, tenant access is a `user ↔ tenant` membership, and access tokens are workspace-scoped. It is not a full application server: callers own HTTP routing, request validation, email delivery, authorization policy, and user-facing flows.

`authkit-go` owns the membership **graph** (global users, tenants, memberships with opaque role strings, credentials, sessions, invitations); the embedding application owns the **policy** (what the role strings mean). This mirrors WorkOS / Auth0 Organizations / Stytch B2B.

## Layers

- `model/`: Public request, response, and database entity structs, plus the sentinel errors (`Err*`) callers branch on.
- `logger/`: Public, optional `Logger` interface (context-first) plus `NopLogger`. Injected via `Config.Logger`.
- `metrics/`: Public, optional `Metrics` interface plus a no-op default and the canonical `Counter*` names. Injected via `Config.Metrics`.
- `ratelimit/`: Public, optional `RateLimiter` interface (aliased as `authkit.RateLimiter`). Injected via `Config.RateLimiter`; consulted before `Login`, `RefreshToken`, and `OTPService.Generate`, with a rejection surfacing as `authkit.ErrRateLimited` (HTTP 429). Key formats are documented in the package.
- `internal/repository/`: PostgreSQL data access (not importable by consumers). Queries are schema-qualified with `authkit.` and rewritten when `DatabaseConnection.IdentitySchema` is configured.
- `internal/service/`: Business logic for global users, memberships, tokens, passwords, API keys, invitations, tenants, OTPs, and encrypted secrets (not importable by consumers; the public contracts are the service interfaces in package `authkit`).
- `migrations/`: PostgreSQL schema used by the default `authkit` schema, embedded in the module and returned by `authkit.Migrations` (see [migrations.md](migrations.md)).
- `integration/`: Docker-backed tests that apply migrations and exercise repository/service behavior against real PostgreSQL.

## Data Model

Core tables:

- `tenants`: Tenant records and allowed email domains.
- `users`: Global user identities — **no** `tenant_id`, **no** `roles`. Email is globally unique, case-insensitively (`UNIQUE (lower(email))`). `token_version` is the identity-level token version (credential events invalidate every workspace's access tokens). An empty `password_hash` means the user has no password and signs in only through a verified sign-in. `email_verified_at` (migration 000005) records when the user proved they own the address.
- `memberships`: The `user ↔ tenant` graph — which identity belongs to which tenant, with `roles` (opaque JSONB strings the embedding app interprets), a per-membership `token_version` (a role change or revoke invalidates only that workspace's access tokens), and a `status` (`active` / `suspended`). Primary key `(user_id, tenant_id)`; both foreign keys cascade on delete.
- `refresh_tokens`: Stored refresh token hashes and session metadata. The refresh token is the **identity session** (user-scoped, no tenant); one login = one family.
- `sessions` (optional migrations 000002 and 000003): Login records scoped by
  application namespace and user, bound to an app installation or (for sessions
  opened by `VerifiedLoginService.OpenSession`) to none, with the sign-in method
  that opened them. Their IDs are refresh-family IDs and signed `sid` claims.
  Records carry independent revocation and idle/absolute expiry; consuming a
  refresh token does not revoke its session. See
  [installation sessions](installation-sessions.md).
- `external_identities` (optional migration 000004): Links from an outside sign-in
  provider's account, keyed by `(provider, subject)`, to one user, with the email
  the provider last reported. Cascades on user delete. See
  [verified sign-in](verified-sign-in.md).
- `api_keys`: Tenant-scoped API key hashes and metadata (`created_by` is a global user id).
- `invitations`: Invitation codes, target email, roles, expiry, and usage limits.
- `verification_codes`: OTPs stored as a keyed HMAC-SHA256 (`code_hash`), never in plaintext, plus purpose, failed-attempt count, expiry, and creation time; keyed by `(email, purpose)` globally (email is a global identity, so an OTP is identity-level, not tenant-scoped).
- `provider_keys`: Tenant-scoped encrypted secrets (`created_by` is a global user id).
- `user_status_changes`: Audit trail of account enable/disable and lock/unlock
  transitions. Written by the library in Go, in the same transaction as the
  status change (there is no DB trigger).

All identifiers are UUIDv7 minted in Go (`uuid.NewV7()`) and represented as 36-char
strings — `varchar(36)` columns in the schema and `string` on the Go API surface;
there is no SQL-side UUID type or generator. (`tenant_id` is the exception: a
caller-supplied free-form identifier, `varchar(255)`.)

## Connection Model

`DatabaseConnection` accepts separate `IdentityRWDB` and `IdentityRODB` handles.

- Writes always use `IdentityRWDB`.
- General reads use `IdentityRODB`.
- Security-sensitive validation paths that must see revocations immediately use `IdentityRWDB`, including API key validation, refresh-token validation/rotation, and `ValidateJWT`'s identity **and** membership reads (so a just-bumped identity or membership `token_version`, a disable/lock, or a membership revoke is observed without replica lag).

This allows applications to use read replicas while avoiding replica-lag acceptance for revoked credentials.

## Health Checks

`New` does not contact the database by default — connection errors surface lazily on
the first query. For readiness/liveness probes, `AuthKit.Ping(ctx)` issues a
`PingContext` to **both** the read-write and read-only handles and wraps the error to
identify which is unreachable. Set `Config.VerifyConnectivity = true` to make `New`
run that check at construction (with a short internal timeout) and fail fast; it is off
by default so construction stays cheap and offline-testable.

## Schema Configuration

The default schema is `authkit`.

Set `DatabaseConnection.IdentitySchema` to use another PostgreSQL schema. The schema name must be a single valid PostgreSQL identifier, such as `authkit`, `identity`, or `custom_identity`. Dotted names and raw SQL are rejected.

The shipped migrations create the default `authkit` schema. For a custom schema, `authkit.Migrations(schema)` returns them with that schema in place of `authkit` (see [migrations.md](migrations.md)).

## Security Assumptions

Callers are responsible for:

- Using TLS for all network traffic.
- Providing high-entropy secrets for JWT signing (or an asymmetric signing key), API key HMACs, refresh-token HMACs, and secret encryption.
- Serving `AuthKit.JSONWebKeySet` when other services check access tokens with the public key, and accepting that those services do not see revocation (only `AuthService.ValidateJWT` does).
- Storing secrets outside source control.
- Enforcing application-specific authorization and role policy.
- Running the OAuth/OIDC client protocol (state, nonce, PKCE, ID-token
  verification) and deciding which providers' email verification to trust, before
  calling `ExternalIdentityService`; and passing `VerifiedLoginService.OpenSession`
  only user ids from their own completed verification.
- Sending OTPs/invitations through a trusted delivery channel.
- Running cleanup jobs for expired API keys, OTPs, invitations, and refresh tokens.
- Configuring branch protection and release controls for their deployment workflow.

Library guarantees:

- API keys are generated with `crypto/rand` and stored only as HMAC-SHA256 hashes.
- Refresh tokens are random opaque strings and stored only as HMAC-SHA256 hashes.
- Refresh-token rotation consumes the old token and stores the replacement in one transaction.
- OTPs are stored only as a keyed HMAC-SHA256 (never plaintext); validation consumes the code atomically within a transaction (`SELECT ... FOR UPDATE`, then `DELETE`).
- Secrets are encrypted with AES-256-GCM before storage.
- Passwords are hashed with bcrypt.
- Access tokens are checked only with configured keys, each in its own algorithm: a token's `kid` must name a configured key, and only HS256 goes without one (see [signing-keys.md](signing-keys.md)).

## Non-Goals

- HTTP middleware, routing, and cookie/session transport.
- Email/SMS delivery.
- OAuth/OIDC provider (authorization server) implementation, and the OAuth/OIDC
  client protocol itself: applications use a client library and pass the verified
  result to `ExternalIdentityService` and `VerifiedLoginService`.
- Role/permission authorization engine.
- Schema migration runner abstraction.
