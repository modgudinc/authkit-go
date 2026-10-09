# Database migrations

authkit's PostgreSQL schema ships inside the module. `authkit.Migrations` returns it
as numbered SQL files, so an application applies it with its own migration tool
instead of copying SQL out of the repository.

## What ships

| Migration | Adds | Needed by |
|-----------|------|-----------|
| `000001_identity_schema` | The `authkit` schema: tenants, users, memberships, invitations, API keys, refresh tokens, OTP codes, provider keys, status history | Every deployment |
| `000002_installation_sessions` | `sessions` | `SessionOptional` and `SessionRequired` |
| `000003_session_sign_in` | `sessions.sign_in_method`; sessions without an installation | Session modes, from the release with `VerifiedLoginService` |
| `000004_external_identities` | `external_identities` | `ExternalIdentityService` |
| `000005_email_verification` | `users.email_verified_at` | Every deployment |
| `000006_refresh_token_replacement` | `refresh_tokens.replaced_by` | `JWTConfig.RefreshGracePeriod` ([refresh-tokens.md](refresh-tokens.md)) |

Each has an `.up.sql` and a `.down.sql`. With a migration tool, apply them all, in
order. The ones a feature needs only add tables and a column that stay empty when
the feature is off. A `.down.sql` reverses its `.up.sql`, and `000001`'s drops the
whole schema.

## Apply them with golang-migrate

[golang-migrate](https://github.com/golang-migrate/migrate) reads the files through
its `iofs` source:

```go
import (
    "errors"

    "github.com/golang-migrate/migrate/v4"
    _ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
    "github.com/golang-migrate/migrate/v4/source/iofs"
    authkit "github.com/modgudinc/authkit-go"
)

func migrateIdentity(databaseURL string) error {
    files, err := authkit.Migrations("") // "" is the default authkit schema
    if err != nil {
        return err
    }
    source, err := iofs.New(files, ".")
    if err != nil {
        return err
    }
    // databaseURL is a pgx5:// URL, for example
    // pgx5://user:pass@host:5432/db?sslmode=require&x-migrations-table=authkit_migrations
    m, err := migrate.NewWithSourceInstance("iofs", source, databaseURL)
    if err != nil {
        return err
    }
    if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
        return err
    }
    return nil
}
```

`x-migrations-table` keeps authkit's version apart from the application's own
migrations, which need a table of their own when they run through golang-migrate
too. Any other tool that runs `NNNNNN_name.up.sql` files in version order works the
same way; the `migrate` CLI can also point at the `migrations/` directory of a
checkout at a release tag.

## A custom schema

An application that sets `DatabaseConnection.IdentitySchema` passes the same name:

```go
files, err := authkit.Migrations("identity")
```

The files are the same SQL with that schema, quoted, everywhere they name the
`authkit` schema. The optional `authkit_rw` and `authkit_ro` roles the migrations
grant to keep their names. `Migrations` refuses a name that `IdentitySchema` would
refuse.

## Migrations never change

A migration that has shipped in a release never changes. Databases have already run
it, and migration tools never run it again, so an edit would reach only new
databases. Schema changes arrive as new numbered migrations, and the CHANGELOG says
when a release needs one. A test pins every file's checksum, so an edit fails CI.

`000001` is frozen as released in v0.20.2. Before v0.20.2 it was edited in place
across `0.x` releases; a database created from an earlier version follows the
upgrade notes in [docs/releases](releases/) to reach the v0.20.2 schema first.

## Moving from SQL applied by hand

If you applied the files yourself, tell your tool what is already there before its
first run. With golang-migrate, apply any of `000002` to `000004` you skipped (they
only add tables and a column), then record the last version you have, for example
`migrate -source "file://migrations" -database "$DATABASE_URL" force 5`, or
`m.Force(5)` in code. Its next `Up` starts after that version.
