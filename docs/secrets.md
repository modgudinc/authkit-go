# Tenant secrets and their keys

`SecretService` keeps secrets a tenant gives your application, such as a provider's
API key or an OAuth token, encrypted at rest with AES-256-GCM. Each value is bound to
its tenant and key name, so a ciphertext copied to another row does not decrypt.

## One key, or a key per tenant

`SecretConfig` takes one of two keys:

- **`EncryptionKey`**: one base64-encoded 32-byte key encrypts every tenant's
  secrets. It is the simple choice when one deployment serves one customer, or when
  tenants need not be kept apart from each other by key.
- **`TenantKey`**: a function that returns each tenant's own 32-byte key. A key that
  leaks exposes only its tenant's secrets, and destroying a tenant's key leaves its
  secrets unreadable wherever they were copied, which is how a tenant's secrets can
  be erased from backups you cannot edit.

`New` refuses a configuration that sets both.

## Keeping tenant keys

`SecretService` calls `TenantKey` on every `Save` and `Get`, so it should answer from
memory. A common shape is envelope encryption: make each tenant a random data key
when you add the tenant, store it encrypted ("wrapped") by a key-encryption key that
never leaves a KMS, and unwrap it the first time it is needed:

```go
var keys sync.Map // tenant id -> []byte, unwrapped data keys

config.SecretConfig.TenantKey = func(ctx context.Context, tenantID string) ([]byte, error) {
    if key, ok := keys.Load(tenantID); ok {
        return key.([]byte), nil
    }
    wrapped, err := loadWrappedKey(ctx, tenantID) // your table, written when the tenant was added
    if err != nil {
        return nil, err
    }
    key, err := kms.Decrypt(ctx, wrapped, []byte(tenantID)) // the tenant id as additional data
    if err != nil {
        return nil, err
    }
    keys.Store(tenantID, key)
    return key, nil
}
```

Whatever `TenantKey` returns as an error comes back from `Save` and `Get`, wrapped, so
`errors.Is` still finds your own sentinels and `context.Canceled`. A key that is not
32 bytes is treated as no key: `ErrSecretEncryptionKeyMissing`.

To erase a tenant's secrets, delete its rows and its wrapped data key, and drop the
key from memory in every process. A backup that still holds the wrapped key can
unwrap it for as long as the key-encryption key exists, so either let such backups
age out or give each tenant a key-encryption key of its own and destroy that.

## Moving from one key to a key per tenant

Both keys store values in the same format. A `TenantKey` that returns the old
`EncryptionKey` for every tenant that has secrets keeps them readable; to move a
tenant to a key of its own, `Get` each of its secrets, switch its key, and `Save`
them again. The same steps rotate one tenant's key (see
[SECURITY.md](../SECURITY.md), "Rotation Expectations").
