# authkit-go v0.14.0

Identity representation change: all identifiers move from `uuid.UUID` to plain Go
`string` (a 36-char UUIDv7), and the schema's id columns become `VARCHAR(36)`. It
contains one **breaking change**, so per the pre-1.0 policy it is a minor bump. This
release also lands a substantial expansion of the PostgreSQL integration test suite.

```bash
go get github.com/modgudinc/authkit-go@v0.14.0
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## Why this release

Identifiers were modelled as `github.com/google/uuid`'s `uuid.UUID` on the public
surface and as the native `uuid` type in the schema. Moving both to a 36-char string
makes the API self-contained — callers no longer need a uuid package to interoperate —
and keeps the on-the-wire/at-rest representation a single, portable form. Ids are still
minted in Go as UUIDv7 (`uuid.NewV7()`), just `.String()`-ed before use.

## Breaking changes

### All identifiers are now `string` (UUIDv7), not `uuid.UUID`

Every id on the public surface is now a Go `string`:

- `model.User.ID`, `model.JWTClaims.UserID`, `model.APIKey.CreatedBy`,
  `model.Invitation.CreatedBy`, `model.Secret.CreatedBy`, the `model.UserStatusChange`
  ids (`ChangedBy` is now `*string`), and `model.RefreshTokenReuseError.{UserID, FamilyID}`.
- Every repository/service method that takes or returns an id, e.g.
  `GetByID(ctx, userID string, tenantID string)`, `Create(...) (string, error)`, and
  `RotateRefreshToken(...) (*model.User, string, error)`.

Callers no longer need `github.com/google/uuid` to interoperate with the API. The JWT
wire format is unchanged — a UUID already serialized as a quoted string — so previously
issued tokens still validate.

### Schema — id columns are now `VARCHAR(36)`

`migrations/000001_identity_schema.up.sql` stores the 11 id columns as `varchar(36)`
instead of the native `uuid` type, with no SQL-side UUID type or generator:

- `users.id`, the three `created_by` columns (invitations / api_keys / provider_keys),
  `api_keys.key_id`, `refresh_tokens.{id, user_id, family_id}`, and
  `user_status_changes.{id, user_id, changed_by}`.

`tenant_id` is intentionally **unchanged** (`varchar(255)`): it is a caller-supplied
free-form identifier, not a minted UUID. Fresh installs get the new column types from a
clean `migrate up`; an existing deployment must `ALTER` those columns to `varchar(36)`
(or recreate the schema) before upgrading.

## Tests / CI

The PostgreSQL integration suite was expanded considerably (total coverage ~55% → ~76%):

- The account status-change **audit trail** end to end, including the nullable
  `changed_by` scan that this release's id change touched.
- **`APIKeyService.Validate`** (happy path plus unknown / malformed / expired / revoked).
- **`InvitationService` accept** — single-use exhaustion and the email-must-match binding.
- The **user** account-status and token-invalidation mutators (lock/unlock/disable/enable,
  set-password, update-roles, increment-token-version), with `StatusHistory`.
- **`RefreshTokenPair`** beyond the happy path: the invalid-token path and the
  post-rotation **account-not-active gate** (disabled and locked) that revokes the
  user's refresh-token family.
- The **`SecretService`** AES-256-GCM encrypt/decrypt round-trip and the
  `(tenant_id, key)` AAD binding (a ciphertext moved to a different key fails to decrypt).
- **Tenant** domain-access management (`ValidateDomainAccess` allow/deny, format validation).
- **User CRUD** and the maintenance **cleanup** jobs (expired api-keys / invitations /
  refresh tokens / verification codes, and old audit rows).
- **JWT issuer/audience**: the unit mismatch matrix (audience mismatch, missing issuer,
  the `ErrInvalidToken` sentinel) plus an end-to-end test that the public
  `JWTConfig.Issuer/Audience` is actually enforced through `AuthService.ValidateJWT`.

## Documentation

- README: the **UUID v7** section now states ids are `string` on the Go surface and
  `varchar(36)` at rest; example signatures/comments updated off `uuid.UUID`.
- `docs/architecture.md`: identifiers documented as Go-minted UUIDv7 stored as
  `varchar(36)` strings, with the `tenant_id` (`varchar(255)`, free-form) exception.

## Upgrading

1. **Drop `uuid.UUID` from your call sites.** Any code that held authkit ids as
   `uuid.UUID` (or passed them to authkit) now uses `string`. If you need to parse or
   validate, `uuid.Parse(theString)` still works; you just no longer have to.
2. **Migrate the schema.** Fresh installs: a clean `migrate up`. Existing installs:
   `ALTER` the 11 id columns listed above to `varchar(36)` (or recreate the schema).
   `tenant_id` does not change.
3. No JWT re-issuance is required — the token wire format is unchanged.

## Verification

`gofmt`, `go vet` (default + `integration`), and `golangci-lint` (default +
`integration`) are clean; standalone `gosec` passes; the unit and PostgreSQL
integration suites (both under `-race`, the integration suite applying the updated
`000001` migration and round-tripping data through the `varchar(36)` columns) pass.

---

Full changes: see [CHANGELOG.md](../../CHANGELOG.md). Licensed under [Apache-2.0](../../LICENSE).
