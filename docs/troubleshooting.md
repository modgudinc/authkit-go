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

- Email matches exactly.
- Code matches.
- Purpose matches.
- Code has not expired.
- Code has not already been consumed.

OTP validation is atomic and single-use.

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
