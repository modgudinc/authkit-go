# Architecture

`authkit-go` is a Go library for tenant-scoped identity primitives. It is not a full application server: callers own HTTP routing, request validation, email delivery, authorization policy, and user-facing flows.

## Layers

- `model/`: Public request, response, and database entity structs.
- `internal/repository/`: PostgreSQL data access (not importable by consumers). Queries are schema-qualified with `authkit.` and rewritten when `DatabaseConnection.IdentitySchema` is configured.
- `internal/service/`: Business logic for tokens, passwords, API keys, invitations, tenants, OTPs, and encrypted secrets (not importable by consumers; the public contracts are the service interfaces in package `authkit`).
- `migrations/`: PostgreSQL schema used by the default `authkit` schema.
- `integration/`: Docker-backed tests that apply migrations and exercise repository/service behavior against real PostgreSQL.

## Data Model

Core tables:

- `tenants`: Tenant records and allowed email domains.
- `users`: Tenant-scoped users. Email uniqueness is scoped by `(tenant_id, email)`.
- `refresh_tokens`: Stored refresh token hashes and session metadata.
- `api_keys`: Tenant-scoped API key hashes and metadata.
- `invitations`: Invitation codes, target email, roles, expiry, and usage limits.
- `verification_codes`: OTP codes, purpose, expiry, and creation time.
- `provider_keys`: Tenant-scoped encrypted secrets.
- `user_status_changes`: Audit trail of account enable/disable and lock/unlock
  transitions. Written by the library in Go, in the same transaction as the
  status change (there is no DB trigger).

All identifiers are UUIDv7 minted in Go (`uuid.NewV7()`); the schema has no
SQL-side UUID generation.

## Connection Model

`DatabaseConnection` accepts separate `IdentityRWDB` and `IdentityRODB` handles.

- Writes always use `IdentityRWDB`.
- General reads use `IdentityRODB`.
- Security-sensitive validation paths that must see revocations immediately use `IdentityRWDB`, including API key validation and refresh-token validation/rotation.

This allows applications to use read replicas while avoiding replica-lag acceptance for revoked credentials.

## Schema Configuration

The default schema is `authkit`.

Set `DatabaseConnection.IdentitySchema` to use another PostgreSQL schema. The schema name must be a single valid PostgreSQL identifier, such as `authkit`, `identity`, or `custom_identity`. Dotted names and raw SQL are rejected.

The provided migration creates the default `authkit` schema. Applications using a custom schema should copy the migration and replace `authkit` with the configured schema name.

## Security Assumptions

Callers are responsible for:

- Using TLS for all network traffic.
- Providing high-entropy secrets for JWT signing, API key HMACs, refresh-token HMACs, and secret encryption.
- Storing secrets outside source control.
- Enforcing application-specific authorization and role policy.
- Sending OTPs/invitations through a trusted delivery channel.
- Running cleanup jobs for expired API keys, OTPs, invitations, and refresh tokens.
- Configuring branch protection and release controls for their deployment workflow.

Library guarantees:

- API keys are generated with `crypto/rand` and stored only as HMAC-SHA256 hashes.
- Refresh tokens are random opaque strings and stored only as HMAC-SHA256 hashes.
- Refresh-token rotation consumes the old token and stores the replacement in one transaction.
- OTP validation consumes the code atomically within a transaction (`SELECT ... FOR UPDATE`, then `DELETE`).
- Secrets are encrypted with AES-256-GCM before storage.
- Passwords are hashed with bcrypt.

## Non-Goals

- HTTP middleware, routing, and cookie/session transport.
- Email/SMS delivery.
- OAuth/OIDC provider implementation.
- Role/permission authorization engine.
- Schema migration runner abstraction.
