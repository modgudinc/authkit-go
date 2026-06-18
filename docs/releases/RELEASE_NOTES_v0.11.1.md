# authkit-go v0.11.1

A patch release with internal-only cleanups — **no public API, behavior, or schema
change**. Safe to upgrade from v0.11.0 with no code changes.

```bash
go get github.com/modgudinc/authkit-go@v0.11.1
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## Changes

- **Integration test suite is lint-clean and gated.** Fixed pre-existing `errcheck`
  (`db.Close`/`rows.Close`), a missing `rows.Err()` check, and gosec G304/G101
  false-positives in the `//go:build integration` tests, and set
  `run.build-tags: [integration]` in `.golangci.yml` so `golangci-lint run` (CI and
  `make lint`) now lints those files instead of skipping them — preventing future
  regressions there.
- **`identity.go` split for readability.** The user status-change audit machinery
  (the `statusChangeActor`/`userStatusSnapshot` types and the `withUserStatusAudit` /
  `readUserStatusForUpdate` / `recordStatusChange` / `insertUserStatusChange` helpers)
  moved to a new `identity_audit.go`. Same package, no behavior change; `identity.go`
  drops to user CRUD/queries.

## Verification

`gofmt`, `go vet` (default + `integration`), and `golangci-lint` (which now includes
the integration-tagged files) are clean; the unit and PostgreSQL integration suites
pass.

---

Full changes: see [CHANGELOG.md](../../CHANGELOG.md). Licensed under [Apache-2.0](../../LICENSE).
