# Security Policy

This project handles authentication and secret-management primitives, so please
report suspected vulnerabilities privately before opening a public issue.

## Supported Versions

This library is pre-1.0. Only the **latest published minor (`0.y`) release line**
receives security fixes; all earlier minor lines are unsupported. Pin a version and
track the latest minor to stay supported. Until 1.0, a minor release may include
breaking changes when required to fix a security issue.

## Reporting

Report security issues **privately** through one of these channels — please do
not open a public issue for a vulnerability:

- **GitHub Private Vulnerability Reporting** (preferred): on this repository, go
  to the **Security** tab and click **"Report a vulnerability"**.
- **Email**: security@modgudinc.com.

You will get an acknowledgement, and we will coordinate a fix and disclosure
timeline with you.

Include:

- Affected package, version, or commit
- Reproduction steps or proof of concept
- Expected impact
- Any suggested mitigation

## Secret Management Expectations

Applications using this library must provide and protect several independent
secrets:

- `JWTConfig.AccessSecret`: signs access-token JWTs
- `JWTConfig.RefreshTokenHMACSecret`: hashes refresh tokens before storage
- `APIKeyConfig.HMACSecret`: hashes API keys before storage
- `OTPConfig.HMACSecret`: hashes OTP codes before storage (required when OTPService
  is used). OTP codes are persisted only as this keyed HMAC, never in plaintext, so
  a read-only database/backup/replica disclosure does not yield usable codes.
- `SecretConfig.EncryptionKey`: encrypts provider secrets with AES-256-GCM

Best practices:

- Generate secrets with a cryptographically secure generator.
- Store secrets in a secret manager or encrypted environment store, not in source
  control, config files, Docker images, shell history, or logs.
- Use separate values for each config field. Do not reuse one secret for JWTs,
  API keys, refresh tokens, and encryption.
- Use different secrets per environment.
- Restrict read access to production secrets to the smallest possible operator
  and runtime set.
- Treat logs, panic traces, metrics labels, and error reports as hostile surfaces;
  never include plaintext API keys, access or refresh tokens, OTPs, passwords, or
  provider secrets. Access tokens are signed but NOT encrypted and carry identity
  claims (including the user's email), so a logged raw token leaks that PII in
  addition to being a usable bearer credential. Minimize PII too: authkit's own logs
  mask email addresses (e.g. `u***@acme.com`) and avoid logging an attacker-controlled
  lookup error alongside the email, so the auth logs are not an account-enumeration
  list. Keep this property when adding log lines, and apply the same care in your
  application logs. If you inject a line-oriented logger (e.g. the standard library
  `log` package), escape untrusted field values — authkit logs some caller-supplied
  fields (such as tenant name and domain) verbatim; structured loggers escape field
  values, but plain line writers do not, so control characters could forge log lines.

Recommended minimum entropy:

- JWT and HMAC secrets: at least 32 random bytes, encoded as base64 or hex.
- `SecretConfig.EncryptionKey`: exactly 32 random bytes, base64-encoded.

Example secret generation:

```bash
openssl rand -base64 32
```

### Secrets in memory

The library does not (and in idiomatic Go cannot reliably) zeroize secret material
after use: decrypted provider secrets, passwords, and the root signing/HMAC/encryption
secrets live in process memory as Go strings/byte slices, which are immutable and may
be copied by the garbage collector, so they cannot be deterministically scrubbed. They
may therefore appear in core dumps, swap, or heap snapshots. If your threat model
requires in-memory secrecy, mitigate at the OS/deployment layer: disable core dumps,
use encrypted swap, prefer short-lived processes, and keep the highest-value keys in a
KMS/HSM rather than passing them in as long-lived process configuration.

## Rotation Expectations

This library supports credential revocation and refresh-token rotation, but it
does not automatically rotate application-supplied root secrets. Applications
must plan root-secret rotation.

Recommended cadence:

- Rotate API keys issued to clients on an application-defined schedule.
- Rotate JWT/HMAC/encryption root secrets after staff access changes, suspected
  exposure, environment compromise, or dependency/build-system compromise.
- Review long-lived production root secrets at least quarterly.

Rotation impact:

- Rotating `JWTConfig.AccessSecret` invalidates all existing access tokens.
- Rotating `RefreshTokenHMACSecret` makes existing stored refresh-token hashes
  unverifiable. Revoke all refresh tokens and require re-login.
- Rotating `APIKeyConfig.HMACSecret` makes existing stored API key hashes
  unverifiable. Reissue API keys or support a planned dual-secret migration in
  application code.
- Rotating `OTPConfig.HMACSecret` makes outstanding OTP codes unverifiable; affected
  users must request a new code. OTPs are short-lived, so this clears on its own
  within the code TTL.
- Rotating `SecretConfig.EncryptionKey` requires decrypting stored secrets with
  the old key and re-encrypting them with the new key.

Suggested emergency rotation steps:

1. Deploy new root secrets.
2. Revoke all refresh tokens or increment user token versions where appropriate.
3. Reissue affected client API keys.
4. Re-encrypt stored provider secrets if the encryption key changed.
5. Review logs and audit trails for misuse.
6. Remove the old secrets from all runtimes and secret stores after verification.

If zero-downtime root-secret rotation is required, wrap this library at the
application layer with key-version metadata or dual-read/single-write logic. For
example, validate API keys against old and new HMAC secrets during a short
migration window, but create only new-key hashes.

## Caller-Owned Controls

This library deliberately leaves some controls to the embedding application. They
are out of scope for the library itself and must be provided by the caller:

- **Login / token-refresh rate limiting.** `AuthService.Login` enforces only a
  per-account failed-login lockout (`MaxFailedLoginAttempts`, then a timed lock).
  That bounds guessing against a *single* account but does NOT stop password
  spraying (one or two guesses each across many accounts) or distributed guessing,
  and `AuthService.RefreshToken` has no throttle at all. Put IP-based and/or global
  rate limiting in front of these endpoints. Refresh tokens themselves are 256-bit
  random and not feasibly guessable, but the endpoint should still be throttled to
  bound abuse and OTP/email cost amplification.
- **Transport security.** Terminate TLS and reject plaintext transport — access and
  refresh tokens are bearer credentials, and access tokens carry identity claims
  (including email) that are signed but not encrypted.
- **Authorization.** The library authenticates and scopes data by tenant, but the
  application decides what an authenticated principal is allowed to do.
- **Database resource limits.** The library uses the caller-provided `*sql.DB`
  handles as-is and issues no server-side timeout. Configure connection-pool bounds
  (`SetMaxOpenConns`/`SetMaxIdleConns`/`SetConnMaxLifetime`) and a server-side
  `statement_timeout`/`lock_timeout`, and pass deadline-bearing contexts — otherwise
  a request under `FOR UPDATE` lock contention (e.g. a failed-login storm against one
  account) can pin connections/row locks and exhaust the pool. See the README
  ("Performance Considerations").
- **Audit retention.** The `user_status_changes` audit table has no expiry; schedule
  `UserService.CleanupStatusChanges` per your retention policy to bound its growth.

## Scope

In scope:

- Token issuance, validation, revocation, and rotation bugs
- API key hashing, validation, or disclosure issues
- Password hashing and verification issues
- OTP replay, purpose confusion, or rate-limit bypasses
- Secret encryption or decryption issues

Out of scope:

- Vulnerabilities in applications that use the library incorrectly
- Missing application-level controls that are documented as caller-owned
- Denial-of-service reports without a practical exploit path
