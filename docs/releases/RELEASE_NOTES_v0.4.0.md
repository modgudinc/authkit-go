# authkit-go v0.4.0

A database-driver release: authkit-go now runs on **pgx**
(`github.com/jackc/pgx/v5`) and the `lib/pq` dependency is gone. The Go API is
**unchanged** — `Config.DatabaseConnection` still takes `*sql.DB` and no
`authkit` signatures changed — so the only upgrade step is swapping your
PostgreSQL driver. It is a **minor (breaking) bump** because existing `lib/pq`
callers must change their connection setup.

```bash
go get github.com/modgudinc/authkit-go@v0.4.0
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## Highlights

- **pgx under the hood, `database/sql` on the surface.** The library still uses
  `database/sql` and accepts your `*sql.DB`, but it now relies on the pgx driver's
  type handling. You bring the pool/lifecycle exactly as before — only the driver
  registration and `sql.Open` driver name change.
- **`lib/pq` removed.** `github.com/jackc/pgx/v5` is the only PostgreSQL driver
  dependency now. No Go version bump (still `go 1.24`).

## Breaking changes

| Change | Migration |
|--------|-----------|
| PostgreSQL driver is now pgx | Replace `_ "github.com/lib/pq"` with `_ "github.com/jackc/pgx/v5/stdlib"` and open with `sql.Open("pgx", dsn)` instead of `sql.Open("postgres", dsn)` |

No `authkit` types or function signatures changed; `Config` still takes `*sql.DB`,
and all service/accessor APIs are identical to v0.3.0.

## Why this is required (not optional)

The repository layer now depends on pgx-specific driver behavior, so a stale
`lib/pq` connection will misbehave at runtime rather than fail to compile:

- Tenant `allowed_domains` (`text[]`) are written with native `[]string`
  parameters, which the `lib/pq` driver does not accept.
- Duplicate-account conflict detection (`ErrUserExists`) matches `*pgconn.PgError`,
  which `lib/pq` does not return.

Switching to the pgx driver resolves both.

## Upgrading from 0.3.x

1. Update the driver import and `sql.Open` call:
   ```go
   import _ "github.com/jackc/pgx/v5/stdlib" // was: _ "github.com/lib/pq"

   db, err := sql.Open("pgx", os.Getenv("DATABASE_URL")) // was: "postgres"
   ```
2. `go mod tidy` (drops `github.com/lib/pq`, adds `github.com/jackc/pgx/v5`).
3. Everything else is unchanged — keep passing your `*sql.DB` handles to
   `authkit.New`. Connection-pool tuning is still the standard `database/sql`
   methods (`SetMaxOpenConns`, …), or pgx DSN parameters (`pool_max_conns=…`) if
   you prefer.

## Verification

`gofmt`, `go vet` (default + `integration`), `golangci-lint`, and `gosec` are
clean; unit and PostgreSQL integration tests pass against the pgx `stdlib`
driver (including tenant array round-trips, `ANY(allowed_domains)` matching, the
`pgconn` unique-violation path, custom-schema quoting, and the multi-statement
migrations), with coverage enforced at ≥ 30% in CI.

---

Full changes: see [CHANGELOG.md](../../CHANGELOG.md). Licensed under [Apache-2.0](../../LICENSE).
