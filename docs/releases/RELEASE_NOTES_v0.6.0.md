# authkit-go v0.6.0

A correctness, security, and error-contract hardening release from a full review
of the library. The headline theme is **matchable errors**: more failure modes
can now be branched on with `errors.Is`. No exported `authkit` function signature
changed and no migration is required.

```bash
go get github.com/modgudinc/authkit-go@v0.6.0
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## Security

- **Encrypted secrets no longer accept an unauthenticated ciphertext format.**
  `decrypt` now requires the `v1:` marker and always authenticates against the
  `(tenant_id, key)` AAD; the legacy prefix-less fallback is removed. Previously
  an attacker who could write the secrets column could strip the marker to bypass
  the cross-row/cross-tenant binding the AAD provides. There are no released
  consumers, so there is no legacy ciphertext to migrate.

## Fixed

- **Audit attribution is explicit, not inferred.** A `user_status_changes` row's
  `changed_by_type` is now taken from the operation's provenance — `system` only
  for the automatic failed-login lockout, `admin` for every explicit admin
  mutation. Before, it was inferred from `failed_login_count >= 5`, so an admin
  locking a user who already had several failed attempts was mis-recorded as
  `system`.
- **`ValidateInvitation` returns `(false, nil)` for a normally-invalid invite.**
  Unknown, expired, or exhausted invitations are a normal "not usable" outcome;
  the error is reserved for genuine (sanitized) storage faults. Callers that
  branch on `err != nil` no longer treat an expired invitation as a server error.
- **`errors.Is(err, ErrNotFound)` now matches the id/name-scoped mutators** that
  previously returned bare strings (user `Update`/`SetPassword`/token-version/
  failed-count/last-login/roles, and the API-key/secret/tenant/invitation/
  refresh-token deletes, and the OTP delete).

## Breaking changes

| Change | Notes |
|--------|-------|
| Prefix-less secret ciphertext is rejected | Only `v1:`-marked, AAD-authenticated ciphertext decrypts. No released consumer wrote the old format. |
| Admin `Lock` no longer increments `failed_login_count` | An explicit admin lock now matches `LockByTenant`; the failed-login counter tracks auth attempts only. |
| `AddAllowedDomain` is idempotent | Re-adding a present domain succeeds; a zero-row result now means the tenant does not exist (`ErrNotFound`). |
| `ValidateInvitation` error semantics | Known-invalid is `(false, nil)`, not `(false, err)`. |

No exported `authkit` function signatures changed.

## Added

- **`ErrPasswordTooWeak`** — strength failures (too short, too long, missing a
  required character class) are matchable. `PasswordStrengthRequirements` gains a
  `MaxLength` (default 72, bcrypt's input cap); over-cap passwords are rejected as
  a clean validation error, including via `HashPassword` for callers that bypass
  `ValidatePasswordStrength`.
- **`ErrSecretEncryptionKeyMissing`** — a missing/invalid
  `SecretConfig.EncryptionKey` now surfaces from the first `SecretService`
  operation as a matchable sentinel instead of an opaque internal error.
- `CreateInvitation` maps the (astronomically rare) server-minted-code collision
  to `ErrInternal` rather than leaking the raw constraint string.

## Upgrading

Drop-in for correctly-configured callers; no schema change. If you match errors
by string instead of `errors.Is`, switch to the sentinels — several paths now
return wrapped sentinels (`ErrNotFound`, `ErrPasswordTooWeak`,
`ErrSecretEncryptionKeyMissing`) where they previously returned bare strings. If
you relied on `ValidateInvitation` returning an error for an expired invitation,
branch on the boolean instead.

## Verification

`gofmt`, `go vet` (default + `integration`), and `golangci-lint` are clean; unit
and PostgreSQL integration tests pass, including new coverage for prefix-less
ciphertext rejection, admin-vs-system audit attribution, the `ErrNotFound`
mutator sweep, the password sentinels, the secret missing-key sentinel, and the
`ValidateInvitation` `(false, nil)` contract.

---

Full changes: see [CHANGELOG.md](../../CHANGELOG.md). Licensed under [Apache-2.0](../../LICENSE).
