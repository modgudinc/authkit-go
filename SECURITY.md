# Security Policy

This project handles authentication and secret-management primitives, so please
report suspected vulnerabilities privately before opening a public issue.

## Supported Versions

This library is pre-1.0; only the latest minor release receives security fixes.
Until 1.0, a minor release may include breaking changes when required to fix a
security issue.

| Version | Supported          |
| ------- | ------------------ |
| 0.8.x   | :white_check_mark: |
| < 0.8   | :x:                |

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
  never include plaintext API keys, refresh tokens, OTPs, passwords, or provider
  secrets. Minimize PII too: authkit's own logs mask email addresses (e.g.
  `u***@acme.com`) and avoid logging an attacker-controlled lookup error alongside
  the email, so the auth logs are not an account-enumeration list. Keep this
  property when adding log lines, and apply the same care in your application logs.

Recommended minimum entropy:

- JWT and HMAC secrets: at least 32 random bytes, encoded as base64 or hex.
- `SecretConfig.EncryptionKey`: exactly 32 random bytes, base64-encoded.

Example secret generation:

```bash
openssl rand -base64 32
```

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
