# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the library is pre-1.0 (`0.x`), minor releases may contain breaking changes.

## [Unreleased]

## [0.1.0] - 2026-06-10

First tagged release. Establishes the multi-tenant identity/auth surface
(users, tenants, JWT + refresh tokens, API keys, OTP, invitations, encrypted
secrets) on PostgreSQL, plus a security-hardening pass across the library.

### Added

- Exported sentinel errors (`model.Err*`, re-exported as `authkit.Err*`) so
  callers can branch with `errors.Is` instead of matching error strings.
- `InvitationService.AcceptInvitation` / `Repository.AcceptInvitation`: validate,
  consume, and create the user in a single transaction, bound to the invitation's
  target email and roles.
- Refresh-token reuse/theft detection via a token `family_id`; presenting an
  already-consumed token revokes the whole family (`model.ErrRefreshTokenReuse`).
- Per-OTP failed-attempt lockout (`MaxOTPValidationAttempts`) and constant-time
  OTP comparison.
- Minimum-length validation (`MinSecretLength`, 32 bytes) for JWT/HMAC secrets in `New()`.
- Optional JWT issuer/audience: `JWTConfig.Issuer` / `JWTConfig.Audience` (and
  `service.WithIssuer` / `service.WithAudience`); when set they are stamped on
  generated tokens and required during validation.
- `logger.NopLogger`, a safe no-op `Logger` implementation.
- Unit tests for security-critical auth paths (login lockout/enumeration,
  `ValidateJWT` revocation/disabled/locked, JWT `alg=none` rejection) and
  integration tests for refresh-token reuse and atomic invitation acceptance.
- `REVIEW.md` capturing the OSS-readiness review.
- Configurable identity schema with validated, quoted schema names.
- Docker Compose and opt-in integration tests that validate migrations against PostgreSQL.

### Changed (breaking)

- `OTPService.Generate/Validate/Delete` now take a `tenantID` first argument;
  `verification_codes` is keyed by `(tenant_id, email, purpose)` with a
  `tenant_id` foreign key (OTPs isolated per tenant and per purpose).
- `APIKeyService.GetAPIKey`/`RevokeAPIKey` (and the underlying repository methods)
  now require and are scoped by `tenantID`.
- `UserService.Update/Delete/Enable/Disable/Lock/Unlock/SetPassword/IncrementTokenVersion`
  now take a `tenantID` and are scoped to it; account-cutting actions revoke the
  user's refresh tokens.
- `model.CreateRefreshTokenRequest` gains `FamilyID`; `ConsumeVerificationCode`
  returns `model.OTPConsumeResult`.
- Renamed the project/package surface to authkit-go/authkit and switched the
  default database schema to `authkit`.

### Security

- Login no longer leaks account existence/state: unknown-user and disabled/locked
  paths perform a dummy bcrypt comparison (timing equalization) and return a single
  generic `model.ErrInvalidCredentials`; the specific reason is logged only.
- The token refresh path re-checks account status (enabled/locked/version) before
  minting a new access token; disable/lock/version-bump revoke refresh tokens.
- Refresh-token rotation is atomic (old token consumed and replacement stored in
  one write-side transaction).
- Repository not-found paths (users, tenants, API keys, invitations, OTPs,
  secrets) return `model.ErrNotFound` instead of raw driver errors.
- JWT validation pins the exact algorithm (`HS256`), requires an `exp` claim, and
  applies a clock-skew leeway.
- Email is normalized (trimmed + lowercased) at login, user creation, lookups, and
  OTP operations, so casing/whitespace can't fork or hide accounts.
- Token/API-key validation failures (untrusted input) are logged at Warn instead
  of Error to prevent log floods.

### Fixed

- README/`docs` examples referenced request types under the `service` package
  (they live in `model`); call sites updated for the new tenant-scoped signatures.
- OTP logging is safe when no logger is configured; OTP purpose is enforced during validation.
- `model.Secret` `db` struct tags now match the `provider_keys` columns.

### CI

- Integration tests now produce a cross-package coverage profile and the build
  fails if total coverage drops below 30%.

[Unreleased]: https://github.com/modgudinc/authkit-go/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/modgudinc/authkit-go/releases/tag/v0.1.0
