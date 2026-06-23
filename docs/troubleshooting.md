# Troubleshooting

## `RW db connection for identity schema is required`

`authkit.New` requires both `IdentityRWDB` and `IdentityRODB`. If you do not use read replicas, pass the same `*sql.DB` for both.

## `identity schema must be a valid PostgreSQL identifier`

`IdentitySchema` must be a single PostgreSQL identifier, such as `authkit` or `custom_identity`.

Invalid examples:

- `authkit.public`
- `authkit;drop`
- `identity-schema`
- `2identity`

## `relation "authkit.users" does not exist`

The migration has not been applied, or it was applied to a different schema.

For local validation:

```bash
make postgres-up
make test-integration
```

For a custom schema, copy the migration and replace `authkit` with your configured schema name.

## Integration Tests Cannot Connect To PostgreSQL

Start the Docker Compose service:

```bash
make postgres-up
```

The default test database URL is:

```text
postgres://authkit_test:authkit_test@localhost:55432/authkit_test?sslmode=disable
```

Override it with `IDENTITY_TEST_DATABASE_URL` when needed.

## Login Always Fails

Check:

- The user exists in the requested `tenant_id`.
- The password stored in `users.password_hash` is a bcrypt hash, not plaintext.
- The user is enabled.
- The user is not locked.
- The read connection can see the latest user row.

## JWT Validation Fails After Logout-All Or Password Change

This is expected. `LogoutAll` increments `users.token_version`; old access tokens fail validation once the current user version differs from the token claim.

## Refresh Token Fails After One Use

This is expected. Refresh tokens rotate. A successful refresh consumes the old token and returns a replacement.

## OTP Validation Fails

Check:

- `OTPConfig.HMACSecret` is set. `OTPService.Generate` and `Validate` return
  `ErrOTPSecretMissing` when it is empty (OTP codes are stored as a keyed HMAC).
- The **same** `OTPConfig.HMACSecret` is used at generation and validation — codes are
  keyed HMACs, so a changed secret makes every outstanding code unverifiable.
- Email, code, and purpose all match exactly.
- The code has not expired or already been consumed.
- Not locked out: after `MaxOTPValidationAttempts` (5) failed guesses the code is
  invalidated and `Validate` returns `ErrOTPLockedOut` — the caller must request a new code.

OTP validation is atomic and single-use.

## Requests Rejected With `ErrRateLimited` (429)

If you set `Config.RateLimiter`, `Login`, `RefreshToken`, and `OTPService.Generate`
consult it and return `authkit.ErrRateLimited` (map to HTTP 429) when it rejects.

- Your `RateLimiter.Allow` should return `(false, nil)` to **reject** and an `error`
  only for a backend fault. On an error the library **fails open** (the operation
  proceeds) and increments `authkit_rate_limiter_error_total` — a sustained nonzero
  rate there means your limiter backend is degraded.
- The key passed to `Allow` is `login:<tenant>:<ip|email:...>`, `refresh:<ip>`, or
  `otp:<tenant>:<email>:<purpose>` — bucket on it directly.
- `ValidateJWT` is **not** rate-limited (it's a local signature/DB check), so a 429
  only originates from the login/refresh/OTP-generation paths.

## Database Errors Only Appear On The First Query

By design, `New` does **not** contact the database — a bad DSN or down server surfaces
on the first service call, not at construction. To fail fast at startup set
`Config.VerifyConnectivity = true` (pings both handles with a short timeout). For
readiness/liveness probes call `AuthKit.Ping(ctx)`, which pings both the read-write and
read-only handles and returns an error naming whichever is unreachable.

## API Key Validation Fails

Check:

- Key uses the `sk_live_` prefix.
- Key has not expired.
- The same `APIKeyConfig.HMACSecret` is used for creation and validation.
- The key has not been revoked.

## Secret Encryption Fails

`SecretConfig.EncryptionKey` must be a base64-encoded 32-byte value.

One way to generate a key:

```bash
openssl rand -base64 32
```

Store it in a secret manager or environment variable, not in source control.

## Mapping Errors To HTTP Status Codes

Branch on the exported sentinels with `errors.Is(err, authkit.Err…)` — never match on
`err.Error()`. A suggested mapping (treat anything unrecognized, including
`authkit.ErrInternal`, as **500** — never as a 401):

| Sentinel(s) | HTTP |
|---|---|
| `ErrInvalidCredentials`, `ErrInvalidToken`, `ErrTokenRevoked`, `ErrInvalidRefreshToken`, `ErrRefreshTokenReuse`, `ErrInvalidAPIKey`, `ErrInvalidOTP`, `ErrOTPLockedOut`, `ErrIncorrectPassword` | 401 |
| `ErrAccountDisabled`, `ErrAccountLocked` | 403 |
| `ErrNotFound` | 404 |
| `ErrUserExists` | 409 |
| `ErrRateLimited`, `ErrOTPRateLimited` | 429 |
| `ErrInvalidInput`, `ErrValueTooLong`, `ErrPasswordTooWeak` | 400 |
| `ErrSecretEncryptionKeyMissing`, `ErrOTPSecretMissing`, `ErrInternal`, anything else | 500 |

`ErrSecretEncryptionKeyMissing`/`ErrOTPSecretMissing` are construction-time
misconfigurations (a required secret wasn't provided), so they're operator errors → 500.
See the README "Error Handling" section for the canonical sentinel list and an example
`switch`.
