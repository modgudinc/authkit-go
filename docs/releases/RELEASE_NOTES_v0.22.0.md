# authkit-go v0.22.0

A key of its own for each tenant's secrets. `SecretService` can now encrypt each
tenant's secrets under that tenant's own key instead of one key for everyone, so a
key that leaks exposes one tenant, and destroying a tenant's key leaves its secrets
unreadable wherever they were copied. The release also carries dependency and CI
updates.

```bash
go get github.com/modgudinc/authkit-go@v0.22.0
```

Nothing changes until you set the new option: an application that keeps
`SecretConfig.EncryptionKey` behaves exactly as on v0.21.0, and no migration is
needed.

## Highlights

- **`SecretConfig.TenantKey`**: in place of `EncryptionKey`, a function that returns
  each tenant's own 32-byte AES-256 key. `SecretService` calls it on every `Save` and
  `Get`, so it should answer from memory. Its error comes back from `Save` and `Get`
  wrapped, so `errors.Is` still finds your own sentinels and `context.Canceled`; a
  key that is not 32 bytes is `ErrSecretEncryptionKeyMissing`. `New` refuses a
  configuration that sets both keys.
- **Envelope encryption**: the guide shows the common shape. Make each tenant a
  random data key when you add the tenant, store it wrapped by a key-encryption key
  that never leaves a KMS (with the tenant id as additional data), and unwrap it the
  first time it is needed. Guide:
  [secrets.md](https://github.com/modgudinc/authkit-go/blob/v0.22.0/docs/secrets.md).
- **Same stored format**: values are stored as with `EncryptionKey`, still bound to
  their tenant and key name, so moving to a key per tenant needs no data migration.

## Security

A tenant's secrets are only as separate as their keys: with `TenantKey`, reading one
tenant's secrets needs that tenant's key, and a leaked key exposes no other tenant.

To erase a tenant's secrets, delete its rows and its wrapped data key, and drop the
key from memory in every process. A backup that still holds the wrapped key can
unwrap it for as long as the key-encryption key exists, so let such backups age out,
or give each tenant a key-encryption key of its own and destroy that.

Security reports now go only through GitHub Private Vulnerability Reporting (the
**Security** tab, "Report a vulnerability"); the security email address is retired.
As before, only the latest minor release line receives security fixes, which is now
0.22.

## Upgrade notes

1. Upgrade the library. Go 1.26 or newer is still required, and there is no new
   migration.
2. If you build `SecretConfig` with a positional literal, switch it to keyed fields;
   it gains `TenantKey`.
3. To move to a key per tenant, set `TenantKey` and drop `EncryptionKey`. Have it
   return the old `EncryptionKey` (decoded) for every tenant that already has
   secrets, so they stay readable. To give such a tenant a key of its own, `Get` each
   of its secrets, switch its key, and `Save` them again; the same steps rotate one
   tenant's key.

The [CHANGELOG](https://github.com/modgudinc/authkit-go/blob/v0.22.0/CHANGELOG.md#0220---2026-10-18)
lists every change.

## Dependencies and CI

- `golang.org/x/crypto`: v0.57.0 → v0.58.0, with indirect `golang.org/x/sync`
  v0.24.0 and `golang.org/x/text` v0.43.0.
- Pinned actions: upload-artifact v7.0.2 and CodeQL SARIF upload v4.38.3.
- The test PostgreSQL is pinned to `postgres:16-alpine` by tag and digest, in CI and
  `docker-compose.yml`, and govulncheck scans with the latest Go release.
- The repository has issue and pull request templates, Dependabot updates, an
  OpenSSF Scorecard workflow and a code of conduct.

[Full changes since v0.21.0](https://github.com/modgudinc/authkit-go/compare/v0.21.0...v0.22.0).
