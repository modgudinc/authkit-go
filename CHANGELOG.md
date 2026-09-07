# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the library is pre-1.0 (`0.x`), minor releases may contain breaking changes.

## [Unreleased]

### Added

- Optional installation-bound sessions with Disabled (default), Optional and
  Required modes; separate installation login/validation and session-management
  interfaces, stable signed `sid`, scoped revocation and bounded session lifetime.
- Additive migration 000002. Default mode remains usable with the original schema.
- Session integration coverage for token rotation, workspace switching, logout,
  cross-user/application isolation, expiry, custom schemas, transaction rollback,
  concurrent revocation/reuse and legacy compatibility.

### Security

- Bound access/refresh credentials cannot downgrade to legacy validation when
  session data is absent or session support is disabled. Primary-database checks
  enforce revocation. Bound sessions retain their login's identity token version.
- Opt-in account-wide revocation coordinates user/session/token writes; normal
  session revocation leaves other installations valid.

### Compatibility

- Existing named service interfaces and auth request/response shapes are unchanged.
  `Config` and `JWTClaims` gain fields; positional literals for these structs need
  keyed fields. See the installation-session guide for migration/rollback ordering.

## [0.20.1] - 2026-07-02

### Added

- **Guarded membership mutations** — `MembershipService.RemoveGuarded` and
  `UpdateRolesGuarded`. Each is the plain `Remove` / `UpdateRoles` plus a last-holder
  safety guard: the mutation is refused (new `ErrLastRoleHolder` sentinel; map to HTTP
  409) when it would leave the tenant with **no active member holding a caller-named
  role** — e.g. removing or demoting a workspace's last Admin. Roles stay opaque: the
  caller passes the `requireRole` string to preserve (an empty string disables the
  guard, matching `Remove` / `UpdateRoles`).

### Security

- The guarded methods run the check-and-mutate in a single transaction serialized per
  tenant by a **transaction-scoped advisory lock** (`pg_advisory_xact_lock`), and assert
  the invariant on the post-mutation state. Concurrent removals/demotions — even from
  different processes or replicas — can therefore never race a tenant below one active
  holder of the required role; a naive application-level check (list-then-mutate) cannot
  make that guarantee across instances.

## [0.20.0] - 2026-07-01

The **decoupled-identity** model — a large, breaking rework of authkit's identity model,
in the pre-1.0 (`0.x`) line. authkit had no production identity data, so the `000001`
schema was edited in place — there is **no data migration**.

### Added

- **Global user identities + tenant memberships.** A user is a global identity (no
  tenant, no roles); a `memberships` row grants a user access to a tenant with opaque,
  application-interpreted role strings. New `MembershipService`
  (`Add`/`Remove`/`UpdateRoles`/`Get`/`ListByUser`/`ListByTenant`/`CountByTenant`);
  `Remove` is a soft-revoke (suspends the membership and bumps its `token_version`),
  `Add` is an idempotent upsert (re-grant/reactivate).
- **Workspace-scoped access tokens** carrying both `token_version` (identity,
  `users.token_version`) and `membership_token_version` (`memberships.token_version`);
  `tenant_id` and `roles` come from the active membership.
- **`AuthService.LoginByEmail`** (workspace-agnostic login that opens the session and
  returns the user's memberships to choose from) and **`MintWorkspaceToken`**
  (select/switch workspace from an existing identity session — no re-login).
- **`ErrNoActiveMembership`** sentinel (valid credentials but not an active member of
  the requested tenant; map to HTTP 403) and **`WorkspaceTokenResponse`**.

### Changed (breaking)

- `users` is global: `tenant_id` and `roles` removed; email is globally unique
  (`UNIQUE (lower(email))`). `User`, `CreateUserRequest`, `UpdateUserRequest`,
  `JWTClaims` (adds `membership_token_version`), and `LoginResponse` (adds
  `Memberships`) change accordingly.
- `UserService` is identity-level (keyed by user id / email); `Count` and `UpdateRoles`
  are removed — roles move to `MembershipService.UpdateRoles`, member counts to
  `MembershipService.CountByTenant`.
- `AuthService.Login` now requires an active membership in `TenantID`; `RefreshToken`
  takes the target `TenantID`; `LogoutAll(userID)` and `ChangePassword` are
  identity-level (no tenant); `ValidateJWT` checks the identity **and** membership
  `token_version` plus membership status.
- OTP is keyed by `(email, purpose)` — tenant dropped from `OTPGenerateRequest` /
  `OTPValidateRequest` and `OTPService.Delete`.
- `InvitationService.Accept` returns `(userID, created, error)` and reuses an existing
  global identity for the email (or creates one) before granting the invited membership.

### Security

- `ValidateJWT` reads the identity and membership from the primary (no replica-lag
  fail-open); a role change or revoke invalidates only that workspace's access tokens,
  while a credential event invalidates all of them.
- Refresh-token reuse detection is preserved across the new refresh flow: a replayed
  consumed token revokes the whole family, bumps the identity `token_version`, and
  surfaces `ErrRefreshTokenReuse`.
- `ErrNoActiveMembership` is an authorization outcome and never revokes the identity
  session (the user keeps access to their other workspaces).

[Unreleased]: https://github.com/modgudinc/authkit-go/compare/v0.20.1...HEAD
[0.20.1]: https://github.com/modgudinc/authkit-go/releases/tag/v0.20.1
[0.20.0]: https://github.com/modgudinc/authkit-go/releases/tag/v0.20.0
