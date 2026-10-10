# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the library is pre-1.0 (`0.x`), minor releases may contain breaking changes.

## [Unreleased]

### Added

- `VerifiedLoginService.OpenSession` opens a session for a user the application has
  verified itself (an OAuth or OIDC provider, an email link, an OTP, a passkey, an
  approved device code). It works in every session mode, with or without an
  installation, applies the login account gates and workspace selection, and
  records the sign-in method on the session (`Session.SignInMethod`; `"password"`
  for password logins). Sessions with no installation are allowed in Optional and
  Required modes.
- Users without a password: an empty `PasswordHash` in `UserService.Create` or
  `InvitationService.Accept`, and `User.HasPassword`.
- `ExternalIdentityService` (`Resolve`, `Link`, `Unlink`, `Get`, `ListByUser`) links
  an outside provider account, keyed by provider and the provider's subject, to one
  user. `Resolve` finds a returning sign-in by subject, links a first sign-in by a
  provider-verified email only to a user whose own email is verified, who has no
  password and who has no other account at that provider, and can create a
  passwordless user. The OAuth/OIDC client protocol
  stays with the application.
- Sentinels `ErrIdentityLinkRequired`, `ErrIdentityAlreadyLinked` and
  `ErrEmailNotVerified`; counters `authkit_verified_login_total{method}` and
  `authkit_identity_link_refused_total{reason}`; `no_password` reason on
  `authkit_login_failure_total`.
- Migrations `000003_session_sign_in` (session sign-in method, sessions without an
  installation) and `000004_external_identities`. Guide:
  [docs/verified-sign-in.md](docs/verified-sign-in.md).
- Email verification state: `User.EmailVerifiedAt`, `User.HasVerifiedEmail` and
  `UserService.MarkEmailVerified` (migration `000005_email_verification`). Users
  that `Resolve` creates start verified; invitation acceptance and
  `UserService.Create` do not set it. The guide shows passwordless sign-in by
  emailed code with `OTPService`, `MarkEmailVerified` and `OpenSession`.
- Asymmetric access-token signing: `JWTConfig.SigningKey` (Ed25519 as EdDSA, ECDSA
  P-256 as ES256, RSA of 2048 bits or more as RS256; any `crypto.Signer`, so KMS and
  HSM keys work) stamps a key id on each token, and `JWTConfig.VerificationKeys`
  accepts further public keys while switching or rotating keys. Key ids default to
  the RFC 7638 thumbprint. `AuthKit.JSONWebKeySet` returns the public keys as a JSON
  Web Key Set to serve at a jwks_uri, and `ParsePrivateKeyPEM` / `ParsePublicKeyPEM`
  read PEM keys. `AccessSecret` is optional when a signing key is set, and validates
  older HS256 tokens until it is removed. Guide:
  [docs/signing-keys.md](docs/signing-keys.md).
- `Migrations(schema)` returns the SQL migrations embedded in the module, as numbered
  `.up.sql`/`.down.sql` files for golang-migrate (`source/iofs`) or any tool that
  runs them in order, so applications no longer copy them from the repository. For a
  custom `IdentitySchema` it returns them with that schema in place of `authkit`,
  replacing the hand edit. Guide: [docs/migrations.md](docs/migrations.md).
- `JWTConfig.RefreshGracePeriod` lets a client retry a refresh whose response it lost
  (a timeout, a process killed before it saved the new token) instead of being signed
  out everywhere as a suspected thief. A consumed refresh token can be exchanged again
  within the period while its replacement has never been used; the unused replacement
  is revoked. Once the replacement is used, the old token is reuse as before, so theft
  is still caught on the second of the two refreshes. Off by default. Migration
  `000006_refresh_token_replacement`, counter `authkit_refresh_token_retry_total`.
  Guide: [docs/refresh-tokens.md](docs/refresh-tokens.md).
- Sign-in history: with `Config.RecordSignIns`, every sign-in attempt on an existing
  account (password logins and `OpenSession`) is recorded with its method,
  workspace, session, installation, IP address, user agent and device name, and the
  reason for a refusal (`bad_password`, `no_password`, `account_disabled`,
  `account_locked`, `no_membership`). `AuthKit.SignInHistoryService` lists a user's
  attempts newest first and prunes old ones (`model.SignInEvent`). Recording is
  best-effort; a failed write counts as `authkit_best_effort_write_failure_total`
  with `op="record_sign_in"`. Off by default. Migration `000007_sign_in_events`.
  Guide: [docs/sign-in-history.md](docs/sign-in-history.md).
- Passkeys: `AuthKit.PasskeyService` stores WebAuthn credentials (passkeys and
  security keys) and gives each user a random 64-byte user handle per relying party
  (`User`, `UserByHandle`), for the application's WebAuthn library to run the
  ceremonies with. `Register` keeps the credential record (`model.Passkey`) and
  refuses a credential ID already registered at the RP ID
  (`ErrPasskeyAlreadyRegistered`). `RecordUse` writes a sign-in's counter and flags
  back and refuses a signature counter that did not go up (`ErrPasskeyCloned`,
  counter `authkit_webauthn_clone_warning_total`). `List`, `Rename` and `Remove`
  manage a user's passkeys. Migration `000008_passkeys`. Guide, with go-webauthn:
  [docs/passkeys.md](docs/passkeys.md).

### Security

- Password login for a user without a password fails like a wrong password (dummy
  bcrypt comparison, `ErrInvalidCredentials`) and does not count toward the
  failed-login lockout. `ChangePassword` refuses such a user.
- `Resolve` refuses to link by email to an account whose own email is not
  verified or that has a password (pre-account hijacking), or that is linked to
  another account at the same provider (recycled addresses), and an unverified
  email never finds an account. The `email_unverified` reason joins
  `authkit_identity_link_refused_total`.
- `ValidateInstallationJWT` refuses a session that has no installation.
- Access-token validation picks the key from the token's `kid` and accepts only that
  key's algorithm; a token without a `kid` is accepted only as HS256, and only while
  `AccessSecret` is set. An HS256 token that carries a `kid` is now refused. authkit
  has never put a `kid` on its HS256 tokens, so tokens it issued are unaffected.

### Changed

- Migrations are frozen once released: `000001` stays as released in v0.20.2, and
  schema changes arrive as new numbered migrations. A test pins every migration's
  checksum.
- Update `golang.org/x/crypto` to v0.57.0, which requires Go 1.26 (0.20.x needed
  1.25), with indirect updates to `golang.org/x/sync` v0.23.0 and
  `golang.org/x/text` v0.42.0. Update `github.com/jackc/pgx/v5` to v5.11.0.
- Update pinned CI actions: checkout v7.0.1, setup-go v7.0.0, gosec v2.29.0,
  govulncheck-action v1.1.0 and CodeQL SARIF upload v4.37.9. CI lints with
  golangci-lint v2.14.0, since v2.6.0 cannot load a module that targets Go 1.26.

### Fixed

- `Login` and `LoginByEmail` reported any failure to read the user, such as an
  unreachable database or a missing migration, as `ErrInvalidCredentials`, so an
  outage looked like wrong passwords. They now return an error wrapping `ErrInternal`
  (map it to 500); only an unknown email is still `ErrInvalidCredentials`.
  `APIKeyService.Validate` did the same with `ErrInvalidAPIKey` and is fixed the same
  way.
- A sign-in or refresh whose `SessionInfo.IPAddress` was not a bare address, such as
  an `http.Request`'s `RemoteAddr` (`host:port`) or an `X-Forwarded-For` list, failed
  with `ErrInternal` because PostgreSQL refused it. The host of a `host:port` is now
  stored, and an address that does not parse is left out.

### Upgrade

- Build with Go 1.26 or newer.
- Every application must apply migration 000005 before deploying this release:
  every user query reads `users.email_verified_at`. It only adds a nullable column,
  so it is safe while the previous release runs. Existing users start unverified.
- Applications with session support enabled (Optional or Required) must apply
  migration 000003 before deploying this release; session queries read its new
  column. It is safe to apply while the previous release runs. Disabled mode needs
  neither 000003 nor 000004 unless it uses `ExternalIdentityService` (000004).
- Applications that set `JWTConfig.RefreshGracePeriod` must apply migration 000006
  first. It only adds a nullable column; code without a grace period never touches it.
- Applications that set `Config.RecordSignIns` must apply migration 000007 first. It
  only adds a table; code that does not record sign-ins never touches it.
- Applications that use `PasskeyService` must apply migration 000008 first. It only
  adds tables; other code never touches them.
- Existing interfaces, request and response types are unchanged; the new calls are
  on new interfaces (`AuthKit.VerifiedLoginService`, `AuthKit.ExternalIdentityService`,
  `AuthKit.SignInHistoryService`, `AuthKit.PasskeyService`), except `UserService.MarkEmailVerified`, which,
  like 0.20.1's `MembershipService` additions, extends an interface authkit returns.
  `model.Session` gains `SignInMethod`, `model.User` gains `EmailVerifiedAt`,
  `JWTConfig` gains `SigningKey`, `VerificationKeys` and `RefreshGracePeriod`, and
  `Config` gains `RecordSignIns` (positional literals of either need keyed fields).

## [0.20.2] - 2026-09-07

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

### Changed

- Update `golang.org/x/crypto` to v0.55.0, with indirect updates to
  `golang.org/x/sync` v0.22.0 and `golang.org/x/text` v0.41.0.
- Update pinned CI actions: checkout v7.0.0, setup-go v6.5.0,
  CodeQL SARIF upload v4.36.3 and golangci-lint-action v9.3.0.

### Compatibility (source-breaking for positional struct literals)

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

[Unreleased]: https://github.com/modgudinc/authkit-go/compare/v0.20.2...HEAD
[0.20.2]: https://github.com/modgudinc/authkit-go/releases/tag/v0.20.2
[0.20.1]: https://github.com/modgudinc/authkit-go/releases/tag/v0.20.1
[0.20.0]: https://github.com/modgudinc/authkit-go/releases/tag/v0.20.0
