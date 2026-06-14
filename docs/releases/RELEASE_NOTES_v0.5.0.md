# authkit-go v0.5.0

An identifier-generation overhaul plus a migration consolidation. Because no
released version has a consumer yet, the migration set is collapsed to a single
`000001_identity_schema` that represents the final schema. **Breaking** (fine
pre-1.0): this is a **fresh-schema baseline**, not an in-place upgrade from an
earlier 0.x.

```bash
go get github.com/modgudinc/authkit-go@v0.5.0
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## Highlights

- **UUIDv7 minted in Go, everywhere.** The schema has no SQL-side UUID generation:
  all `id`/`family_id` column defaults, the `uuid_generate_v7()` generator, and the
  now-unused `pgcrypto` extension are gone. Every id is supplied by the application
  with `uuid.NewV7()` — a single, consistent source of time-ordered ids.
- **Status-change audit moved into the app.** The `record_status_change` database
  trigger is replaced by Go that writes `user_status_changes` rows in the **same
  transaction** as the status change. Behavior is preserved exactly: one row per
  real `is_enabled`/`is_locked` transition, the same `status_type` /
  `changed_by_type` (`system` at/above the lockout threshold, else `admin`) /
  metadata, and `changed_by` left NULL.
- **One migration file.** 000002/000003/000004 are folded into
  `000001_identity_schema`; the standalone files are removed.

## Breaking changes

| Change | Notes |
|--------|-------|
| Single consolidated schema migration | Apply `000001_identity_schema.up.sql` to a **fresh** database. The new 000001 is `CREATE TABLE IF NOT EXISTS …`; it is not an `ALTER`-based upgrade of an older schema. |
| No SQL-side UUID generation | Ids must come from the application (the library already does this). Direct SQL inserts must supply the id. |
| Audit written by the library | The status mutators are now transactional and require the read-write connection (they already did). |

No `authkit` Go API signatures changed.

## Removed

- The `auth_events` table (never written or read by the library).
- `uuid_generate_v7()`, the `record_status_change` trigger + function, all UUID
  column defaults, and the `pgcrypto` extension.

## Upgrading

There are no released consumers, so treat this as the baseline schema: apply the
single `000001_identity_schema.up.sql` to a fresh database. Anyone who applied an
earlier 0.x schema should recreate it from the new 000001.

## Verification

`gofmt`, `go vet` (default + `integration`), `golangci-lint`, and `gosec` are
clean; unit and PostgreSQL integration tests pass against the consolidated schema
(including audit round-trips — admin vs system attribution, transition-only rows,
Go-minted UUID ids — and the post-consolidation schema assertions), with coverage
enforced at ≥ 30% in CI.

---

Full changes: see [CHANGELOG.md](../../CHANGELOG.md). Licensed under [Apache-2.0](../../LICENSE).
