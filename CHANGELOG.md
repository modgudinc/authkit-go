# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the library is pre-1.0 (`0.x`), minor releases may contain breaking changes.

## [Unreleased]

## [0.1.0] - 2026-06-30

Clean-slate first release of authkit-go on the **decoupled-identity** model. This
`v0.1.0` resets the version history — it is **not** a continuation of the earlier
`v0.1.0`–`v0.14.0` pre-release line (those tags have been deleted). authkit had no
production identity data, so the `000001` schema was edited in place (no data migration).

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

### Changed (breaking, relative to the deleted pre-release line)

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

[Unreleased]: https://github.com/modgudinc/authkit-go/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/modgudinc/authkit-go/releases/tag/v0.1.0
