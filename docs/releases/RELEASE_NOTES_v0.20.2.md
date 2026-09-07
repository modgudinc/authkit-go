# authkit-go v0.20.2

Installation-bound sessions let an application revoke one login or installation
while keeping other devices signed in. This release adds that capability as an
opt-in feature, along with dependency and CI updates.

```bash
go get github.com/modgudinc/authkit-go@v0.20.2
```

**Source compatibility:** `Config` and `model.JWTClaims` gain fields. Consumers
using positional literals for either struct must switch to keyed literals.
This is a source-breaking case despite the v0.20.2 version number. Existing named
service interfaces and auth request/response structs retain their contracts.

## Highlights

- Three session modes: `SessionDisabled` (the default), `SessionOptional`, and
  `SessionRequired`. Existing applications keep legacy session behavior unless
  they enable the feature.
- New `InstallationAuthService` methods: `LoginWithInstallation`,
  `LoginByEmailWithInstallation`, and `ValidateInstallationJWT`. New request
  wrappers and interfaces keep existing auth interfaces and mocks unchanged.
- Stable signed JWT `sid` claims identify one login/refresh family. Refresh
  rotation changes the credentials while preserving the session and installation;
  workspace selection preserves that binding too.
- New `SessionService` methods to get/list sessions, revoke one session or all
  sessions for an installation, and clean up expired records. Management is
  scoped to the configured application namespace and supplied user.
- Sliding idle expiry uses `JWTConfig.RefreshExpiry`. A fixed absolute lifetime
  defaults to 30 days when session support is enabled; access-token expiry is
  capped by the session deadline.
- Additive migration `000002_installation_sessions`. The released identity
  migration is unchanged, and Disabled mode still works with the original schema
  without session-table queries.

## Security and lifecycle

Bound-token validation checks live session state on the primary database, along
with the existing account and workspace membership gates. Missing or revoked
sessions fail validation. Bound refresh tokens carry an opaque version marker
covered by their stored HMAC, preventing fallback to legacy validation when
session data is missing or session support is disabled.

Per-session and per-installation revocation invalidates access tokens and refresh
families without changing the account's identity version. Bound logout closes the
session, including when supplied an older consumed token from that family.
Retrying an intentionally revoked session does not trigger another account-wide
refresh-reuse response.

Bound sessions retain the identity token version from login. Account-wide
credential actions invalidate their refresh capability too. Reusing a consumed
token on an active session retains authkit's existing account-wide reuse
response. Serialize refresh and store the replacement pair atomically; a lost
successful refresh response requires re-authentication.

User/session/refresh writes coordinate through database transactions and a
consistent lock order. Tests cover concurrent refresh/revocation, token reuse,
transaction rollback, expiry, and isolation across users and applications.

Installation binding is association and revocation for bearer credentials.
Applications still verify installation enrollment and authorize management
operations. Device-key proof, peer pairing, E2EE and WebSocket management remain
application responsibilities; authkit does not close existing connections.

New sentinels are `ErrSessionDisabled`, `ErrSessionRequired`, and
`ErrSessionRevoked`.

## Upgrade notes

1. Upgrade the library and replace any positional `Config` or `JWTClaims`
   literals with keyed fields. Go **1.25+** remains required.
2. To enable installation sessions, apply
   `000002_installation_sessions.up.sql` after the identity migration. For a
   custom identity schema, substitute its name consistently in both migration
   files. Default Disabled mode does not require this migration.
3. Deploy session-aware code to **every validator before issuing bound tokens**.
   Older code ignores `sid` and cannot enforce session revocation.
4. Configure a consistent namespace, issuer, audience and session mode across the
   application's issuers and validators. Optional mode supports a deliberate
   transition; Required mode requires enrollment-bound login for legacy sessions.
   Do not attach a client-supplied installation ID to an existing legacy refresh
   token to upgrade it.
5. Use `InstallationAuthService.ValidateInstallationJWT` when callers need the
   verified installation identity, or `AuthService.ValidateJWT` for its existing
   claims result with bound-session validation. The lower-level
   `JWTService.ValidateAccessToken` checks cryptographic claims and mode, not
   database revocation.
6. Before rolling back to older validators or dropping the session table,
   invalidate bound credentials or isolate their issuer. New Disabled validators
   reject bound tokens; older validators cannot make that guarantee.

See the [installation-session guide](https://github.com/modgudinc/authkit-go/blob/v0.20.2/docs/installation-sessions.md)
for configuration, enrollment boundaries, API examples, cleanup and rollout details.

## Dependencies and CI

- `golang.org/x/crypto`: v0.53.0 → v0.55.0.
- Indirect modules: `golang.org/x/sync` v0.22.0 and `golang.org/x/text` v0.41.0.
- Pinned actions: checkout v7.0.0, setup-go v6.5.0, CodeQL SARIF upload v4.36.3,
  and golangci-lint-action v9.3.0. The configured golangci-lint binary remains
  v2.6.0.

The unit and PostgreSQL integration suites run under the race detector; CI also
enforces coverage floors, formatting/static checks, gosec and govulncheck.

[Full changes since v0.20.1](https://github.com/modgudinc/authkit-go/compare/v0.20.1...v0.20.2).
