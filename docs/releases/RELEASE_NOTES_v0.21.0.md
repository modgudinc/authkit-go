# authkit-go v0.21.0

Sign-in without a password, and the security around it. An application can now
open a session for a person it verified itself (an outside provider, an email link
or code, a passkey), sign access tokens with an asymmetric or KMS-held key and
publish its JSON Web Key Set, add passkeys and two-factor sign-in, keep a sign-in
history, let a client retry a lost refresh, take the migrations from the module,
and run authkit's calls in its own transaction. The release also carries a
readiness review's security and error-handling fixes.

```bash
go get github.com/modgudinc/authkit-go@v0.21.0
```

> **Breaking (minor release).** Go 1.26 is required, migration `000005` must be
> applied before deploying, and several calls return different errors than in
> v0.20.2. See [Breaking changes](#breaking-changes) and
> [Upgrade notes](#upgrade-notes). Every new feature is off until configured.

## Highlights

- **Verified sign-in** — `VerifiedLoginService.OpenSession` opens a session for a
  user the application has verified itself, in every session mode, with the login
  account gates and workspace selection, and records the method on
  `Session.SignInMethod`. Users can have no password (`User.HasPassword`).
  `ExternalIdentityService` links a provider account to one user; `Resolve` finds
  a returning sign-in by subject and links a first one by email only to a verified,
  passwordless account. Email verification state is `User.EmailVerifiedAt` and
  `UserService.MarkEmailVerified`. Guide:
  [verified-sign-in.md](https://github.com/modgudinc/authkit-go/blob/v0.21.0/docs/verified-sign-in.md).
- **Asymmetric signing keys** — `JWTConfig.SigningKey` takes Ed25519, ECDSA P-256
  or RSA (2048 bits or more), as any `crypto.Signer`, so KMS and HSM keys work.
  Tokens carry a key id, `JWTConfig.VerificationKeys` covers a rotation,
  `AuthKit.JSONWebKeySet` serves the public keys, and `ParsePrivateKeyPEM` /
  `ParsePublicKeyPEM` read PEM keys. `AccessSecret` becomes optional. Guide:
  [signing-keys.md](https://github.com/modgudinc/authkit-go/blob/v0.21.0/docs/signing-keys.md).
- **Passkeys** — `AuthKit.PasskeyService` stores WebAuthn credentials and a user
  handle per relying party for the application's WebAuthn library, and refuses a
  signature counter that did not go up (`ErrPasskeyCloned`). Guide, with
  go-webauthn:
  [passkeys.md](https://github.com/modgudinc/authkit-go/blob/v0.21.0/docs/passkeys.md).
- **Two-factor sign-in** — with `Config.TwoFactorConfig`, `AuthKit.TwoFactorService`
  enrolls an authenticator app (RFC 6238 TOTP) with ten single-use recovery codes.
  A password login for a person with it on stops with `ErrSecondFactorRequired`,
  and `CompleteSecondFactor` finishes it. Guide:
  [two-factor.md](https://github.com/modgudinc/authkit-go/blob/v0.21.0/docs/two-factor.md).
- **Refresh grace period** — `JWTConfig.RefreshGracePeriod` lets a client retry a
  refresh whose response it lost instead of being signed out everywhere; theft is
  still caught once the replacement is used. Guide:
  [refresh-tokens.md](https://github.com/modgudinc/authkit-go/blob/v0.21.0/docs/refresh-tokens.md).
- **Sign-in history** — with `Config.RecordSignIns`, every attempt on an existing
  account is recorded with its method, device and refusal reason, and
  `AuthKit.SignInHistoryService` lists and prunes them. Guide:
  [sign-in-history.md](https://github.com/modgudinc/authkit-go/blob/v0.21.0/docs/sign-in-history.md).
- **Embedded migrations** — `Migrations(schema)` returns the SQL migrations, with a
  custom schema substituted, for golang-migrate or any runner. Released migrations
  are frozen and a test pins their checksums. Guide:
  [migrations.md](https://github.com/modgudinc/authkit-go/blob/v0.21.0/docs/migrations.md).
- **The caller's transaction** — `authkit.WithTx` and `AuthKit.InTx` run authkit's
  calls in a transaction the application owns (a savepoint where authkit would
  begin its own), so its changes commit with the application's, such as an outbox
  row. Signing in and checking credentials still commit on their own. Guide:
  [transactions.md](https://github.com/modgudinc/authkit-go/blob/v0.21.0/docs/transactions.md).

## Breaking changes

- **Go 1.26 or newer** (`golang.org/x/crypto` v0.57.0 requires it).
- **Migration `000005_email_verification` before deploying:** every user query
  reads `users.email_verified_at`. With session support on (Optional or Required),
  `000003_session_sign_in` too.
- **Source:** `UserService` gains `MarkEmailVerified`, so a type that implements it
  (a mock) must add the method. `model.Session`, `model.User`, `JWTConfig` and
  `Config` gain fields, so positional literals of them need keyed fields.
- **Errors:**
  - `Login`, `LoginByEmail`, `APIKeyService.Validate` and `ValidateJWT` return an
    error wrapping `ErrInternal` when they cannot read the user (an outage, a
    missing migration). They returned `ErrInvalidCredentials`, `ErrInvalidAPIKey`
    and `ErrInvalidToken`, so an outage looked like bad credentials.
  - `ValidateJWT` for a disabled account returns `ErrAccountDisabled` (it was
    `ErrTokenRevoked`).
  - `ErrInternal` becomes `ErrTenantExists` for `TenantService.Create` with a taken
    id, and `ErrNotFound` for `APIKeyService.Create` and `InvitationService.Create`
    with an unknown tenant or creator, and for `SessionService.Revoke` and
    `RevokeInstallation` with an unknown user.
  - `UserService.Create` refuses a malformed email and `TenantService.Create` a
    blank id or name (`ErrInvalidInput`); `PasswordService.VerifyPassword` returns
    `ErrIncorrectPassword` for a wrong password.
  - A refresh for a disabled or locked account still matches
    `ErrInvalidRefreshToken`, now also `ErrAccountDisabled` or `ErrAccountLocked`,
    and deletes none of the person's refresh tokens.
  - `Logout` with a bound session's token succeeds after the session was cleaned
    up (it failed with `ErrSessionRevoked`).
- An HS256 access token that carries a `kid` is refused. authkit never put one on
  its HS256 tokens.
- `APIKeyService.Get` and `List` return an empty `APIKey.KeyHash`.
- `User.LastLoginAt` is set only when a login opens a session, and the unlocks
  authkit performs itself are audited as `ChangedByType` `"system"`.

## Security

- **Account takeover:** a wrong old password in `ChangePassword` now counts toward
  the failed-login lockout, `UserService.SetPassword` revokes access tokens issued
  before it, and `TwoFactorService.Verify` refuses a locked or disabled account
  before checking a code. `Resolve` refuses links that would allow pre-account
  hijacking or a recycled address to take an account.
- **Lockout as a weapon:** a refresh for a locked account deleted every refresh
  token the person had, so anyone who knew an email could sign them out everywhere
  with wrong passwords. A lock now pauses the tokens and deletes nothing. The
  lockout no longer shortens an administrator's longer lock, and last-admin guards
  count only enabled accounts.
- **Rate limiting:** a refresh without an IP address shared one bucket with every
  other such refresh; it is now limited per token.
- **Leaks:** rate-limit metric labels and log lines carry only the operation, not
  email or IP addresses; invitation codes no longer appear in error messages or
  logs; API key HMACs are no longer returned to callers.
- **Tokens:** validation picks the key by `kid` and accepts only that key's
  algorithm; `ValidateInstallationJWT` refuses a session with no installation.

## Upgrade notes

1. Build with Go 1.26 or newer.
2. Apply the migrations before deploying, ideally through
   `authkit.Migrations(schema)` instead of copied files. `000005` is required by
   every application, and `000003` with session support on. The rest are needed
   before turning on what uses them: `000004` for `ExternalIdentityService`,
   `000006` for `RefreshGracePeriod`, `000007` for `RecordSignIns`, `000008` for
   `PasskeyService` and `000009` for `TwoFactorConfig`; `000010` grants the sessions
   table to the optional `authkit_rw` and `authkit_ro` roles. Each only adds a
   column, a table, a grant or a looser check, so all of them are safe while
   v0.20.2 runs. Existing users start with an unverified email.
3. Map an error wrapping `ErrInternal` from `Login`, `LoginByEmail`,
   `APIKeyService.Validate` and `ValidateJWT` to a server error (500), not to bad
   credentials, and review the other changed errors above.
4. Add `MarkEmailVerified` to any `UserService` implementation of your own, and
   switch positional `Config`, `JWTConfig`, `model.User` or `model.Session`
   literals to keyed fields.

The [CHANGELOG](https://github.com/modgudinc/authkit-go/blob/v0.21.0/CHANGELOG.md#0210---2026-10-13)
lists every change.

## Dependencies and CI

- `golang.org/x/crypto`: v0.55.0 → v0.57.0, with indirect `golang.org/x/sync`
  v0.23.0 and `golang.org/x/text` v0.42.0. `github.com/jackc/pgx/v5`: v5.10.0 →
  v5.11.0.
- Pinned actions: checkout v7.0.1, setup-go v7.0.0, gosec v2.29.0,
  govulncheck-action v1.1.0 and CodeQL SARIF upload v4.37.9. CI lints with
  golangci-lint v2.14.0.

[Full changes since v0.20.2](https://github.com/modgudinc/authkit-go/compare/v0.20.2...v0.21.0).
