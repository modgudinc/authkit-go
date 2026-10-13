# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the library is pre-1.0 (`0.x`), minor releases may contain breaking changes.

## [Unreleased]

## [0.21.0] - 2026-10-13

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
- Two-factor sign-in: with `Config.TwoFactorConfig` (an encryption key and the
  issuer name apps show), `AuthKit.TwoFactorService` sets up an authenticator app
  (`EnrollTOTP`, then `ConfirmTOTP` with its first code, which returns ten
  single-use recovery codes) and manages it (`Verify`, `Disable`,
  `RegenerateRecoveryCodes`, `Status`). Codes are RFC 6238 TOTP (SHA-1, six digits,
  30 seconds, one step of drift), each accepted once. For a person with it on,
  `Login`, `LoginByEmail` and their `WithInstallation` forms stop after the password
  with `ErrSecondFactorRequired`, a `*model.SecondFactorRequiredError` carrying a
  five-minute challenge, and `CompleteSecondFactor` finishes the login with a code
  or a recovery code. The secret is stored with AES-256-GCM and the recovery codes
  as HMAC-SHA256, under keys derived from the configured one. Sentinels
  `ErrSecondFactorRequired`, `ErrInvalidSecondFactor`, `ErrTwoFactorAlreadyEnabled`
  and `ErrTwoFactorNotConfigured`; failure reason `bad_second_factor`; rate-limit key
  `second_factor:<userID>`. `OpenSession` is unaffected. Off by default. Migration
  `000009_two_factor`. Guide: [docs/two-factor.md](docs/two-factor.md).
- `ErrTenantExists`, returned by `TenantService.Create` for a `tenant_id` that is
  taken (it was `ErrInternal`).
- Migration `000010_sessions_grants` grants the `sessions` table to the optional
  `authkit_rw` and `authkit_ro` roles, which `000002` left out, so a deployment that
  connects as those roles can use installation sessions. It does nothing without the
  roles. An integration test now checks every table against both roles after every
  migration.
- `authkit.WithTx` and `AuthKit.InTx` run authkit's calls in the caller's
  transaction, so what they change commits or rolls back with the caller's own writes,
  such as an outbox row recording the change. Where authkit would begin a transaction
  of its own it sets a savepoint instead, and reads go to the transaction too. Signing
  in and checking credentials ignore it and commit on their own, so failed attempts,
  lockouts and revoked token families stay recorded. Guide:
  [docs/transactions.md](docs/transactions.md).

### Security

- A refresh with no `SessionInfo.IPAddress` was rate-limited under the single key
  `refresh:`, so with a `Config.RateLimiter` a few refreshes by anyone exhausted the
  bucket for every session. Such a refresh is now keyed `refresh:token:<digest>`, a
  truncated SHA-256 of the token, so it is throttled per token.
- Rate-limit keys hold email and IP addresses, and `authkit_rate_limited_total`
  carried the whole key as its `key` label, as did the log line for a limiter error.
  Both now carry only the operation (`login`, `refresh`, `otp`, `second_factor`).
- `InvitationService.Revoke`, `Delete` and `IncrementUseCount` put the invitation
  code, a credential, in their error messages, which the service then logged. The
  messages no longer carry it.
- `APIKeyService.Get` and `List` returned each key's HMAC in `APIKey.KeyHash`
  (hidden from JSON, visible to Go callers). The field is now empty; the hash stays
  in the database for `Validate`.
- A wrong old password in `AuthService.ChangePassword` was not counted anywhere, so
  someone holding a stolen access token could guess the current password without
  limit and then take the account over. It now counts toward the failed-login
  lockout, as a wrong login password or two-factor code does; at the threshold the
  account locks, which also cuts the token off. A successful change resets the count.
- `MembershipService.RemoveGuarded` and `UpdateRolesGuarded` counted a disabled or
  deleted user as the holder that kept a tenant manageable, so a tenant could be left
  with no admin who can sign in. Only members whose accounts are enabled count now; a
  locked account still counts, since a lock lifts by itself.
- The failed-login lockout rewrote `locked_until` on an account that was already
  locked, so an administrator's indefinite or longer lock was shortened to the
  lockout duration by failed attempts (reachable through `TwoFactorService.Verify`).
  A lock still in force is now kept.
- A bound-session refresh-token reuse was logged at Warn without the
  `event=refresh_token_reuse` field the legacy path logs at Error; both now log the
  same.

- Password login for a user without a password fails like a wrong password (dummy
  bcrypt comparison, `ErrInvalidCredentials`) and does not count toward the
  failed-login lockout. `ChangePassword` refuses such a user.
- With two-factor on, a wrong code counts toward the failed-login lockout, and the
  right password alone no longer resets the count: it is reset when the whole
  sign-in succeeds.
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
- A refresh for a disabled or locked account, without an installation session, rotated
  the token, then deleted every refresh token the user had, bound sessions' included.
  The failed-login lockout revokes nothing, so anyone who knew an email could lock the
  account with wrong passwords, and the next refresh from any of the person's devices
  signed them out everywhere; a stolen token replayed later read as unknown rather than
  as reuse. The rotation now refuses such an account before consuming anything and
  deletes nothing, so a lock pauses the account's refresh tokens, as it already did
  for bound sessions. A consumed token is still reuse. `UserService.Disable` and
  `Lock` still revoke the tokens. The error, from `RefreshToken` and
  `ValidateRefreshToken` alike, still matches `ErrInvalidRefreshToken` and now also
  `ErrAccountDisabled` or `ErrAccountLocked`
  ([docs/refresh-tokens.md](docs/refresh-tokens.md#disabled-and-locked-accounts)).
- `UserService.SetPassword` (a reset, or a first password) did not bump the
  identity `token_version`, so access tokens issued before it kept validating until
  they expired, and a password login waiting for its second factor could still
  finish with the old password. It now sets the password and bumps the version in
  one update, as `ChangePassword` does, before revoking the refresh tokens.
- `TwoFactorService.Verify` checked codes on a locked or disabled account, so the
  lockout that wrong codes trip did not stop further guesses, and a right code was
  accepted while the account was locked. It now returns `ErrAccountLocked` or
  `ErrAccountDisabled` before checking any code.

### Changed (breaking)

- `User.LastLoginAt` is set when a login opens a session, after the workspace gate;
  a right password into a workspace the user is not a member of no longer updates it
  (the failed-login count is still reset by the right password).
- `ValidateJWT` checks the account before the token version, so a token of a
  disabled account returns `ErrAccountDisabled` as documented; `UserService.Disable`
  also bumps the token version, which made it `ErrTokenRevoked`. Once re-enabled,
  the old tokens are `ErrTokenRevoked` as before.
- `UserService.Create` refuses a malformed email (`ErrInvalidInput`); it stored any
  string. `TenantService.Create` refuses a blank `TenantID` or `Name`, and its
  domain errors wrap `ErrInvalidInput`, as do `ValidateDomainAccess`'s; they were
  bare strings. `isValidEmail` now also refuses a second `@` in the local part, as
  its doc said.
- `PasswordService.VerifyPassword` returns `ErrIncorrectPassword` for a wrong
  password (it was a bare string); a malformed hash is still a distinct error.
- `UserService.List` and `APIKeyService.List` order by id after `created_at`, so
  rows created in the same instant page without gaps or repeats.
- `ValidateInstallationJWT`, `LoginWithInstallation` and
  `LoginByEmailWithInstallation` read the session once instead of twice. The session
  a login returns is the one it stored, timestamps truncated to microseconds as
  PostgreSQL keeps them, so it compares equal to `SessionService.Get`'s.
- The unlock the library performs itself (an expired lock on sign-in or token
  validation, a right password after failed attempts) is audited with
  `ChangedByType` `"system"`; it said `"admin"`.
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

- `APIKeyService.Create` and `InvitationService.Create` with an unknown tenant or
  creator returned `ErrInternal`; they return `ErrNotFound`, as `MembershipService.Add`
  does. `TenantService.Create` with a taken id returns `ErrTenantExists`.
- `TenantService.Create` and `InvitationService.Create` read the row they had just
  written from the read-only handle, so with a lagging replica they could return
  `ErrNotFound` for a tenant or invitation that exists. They read it from the primary.
- `SessionService.Revoke` and `RevokeInstallation` for an unknown user returned
  `ErrInternal` and logged an internal error; they return `ErrNotFound`.
- `Logout` with a bound session's refresh token failed with `ErrSessionRevoked` once
  `SessionService.CleanupExpired` had deleted the session. Logout is idempotent: it
  succeeds, as for an unknown token.
- Documentation: the `ratelimit` package and SECURITY.md described the OTP key with a
  tenant segment it does not have and left out `LoginByEmail`'s form; README's
  architecture tree and service list, roadmap, `Authorization` header and
  `APIKeyService.Validate` samples, and the lists of calls the rate limiter guards,
  are brought up to date; v0.20.0's release notes link to the repository again.
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
- `ValidateJWT` reported any failure to read the user, such as an unreachable
  database or a cancelled query, as `ErrInvalidToken`, so an outage signed people
  out. It now returns an error wrapping `ErrInternal` (map it to 500); only a user
  that no longer exists is still `ErrInvalidToken`.
- `LoginByEmail` and `VerifiedLoginService.OpenSession`, picking the only active
  workspace themselves, used the membership as the read replica had it. With a
  lagging replica, a role change could make the access token they returned fail
  `ValidateJWT` at once, or a just-revoked membership could still be picked. The
  picked membership is now read again from the primary; when it is no longer active,
  nothing is picked and the caller chooses.

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
- Applications that set `Config.TwoFactorConfig` must apply migration 000009 first:
  with it set, every password login reads the new tables. It only adds tables; code
  without two-factor never touches them.
- Applications that connect as the `authkit_rw` or `authkit_ro` role and use
  installation sessions should apply migration 000010; it only grants.
- Existing interfaces, request and response types are unchanged; the new calls are
  on new interfaces (`AuthKit.VerifiedLoginService`, `AuthKit.ExternalIdentityService`,
  `AuthKit.SignInHistoryService`, `AuthKit.PasskeyService`, `AuthKit.TwoFactorService`), except `UserService.MarkEmailVerified`, which,
  like 0.20.1's `MembershipService` additions, extends an interface authkit returns.
  `model.Session` gains `SignInMethod`, `model.User` gains `EmailVerifiedAt`,
  `JWTConfig` gains `SigningKey`, `VerificationKeys` and `RefreshGracePeriod`, and
  `Config` gains `RecordSignIns` and `TwoFactorConfig` (positional literals of either
  need keyed fields). Callers that read `APIKey.KeyHash` from `Get` or `List` now get
  an empty string.

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

[Unreleased]: https://github.com/modgudinc/authkit-go/compare/v0.21.0...HEAD
[0.21.0]: https://github.com/modgudinc/authkit-go/releases/tag/v0.21.0
[0.20.2]: https://github.com/modgudinc/authkit-go/releases/tag/v0.20.2
[0.20.1]: https://github.com/modgudinc/authkit-go/releases/tag/v0.20.1
[0.20.0]: https://github.com/modgudinc/authkit-go/releases/tag/v0.20.0
