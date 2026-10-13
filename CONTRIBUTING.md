# Contributing

Thanks for your interest in improving authkit-go.

## Development

Run the unit test suite before opening a pull request:

```bash
make lint
make test
```

`make test` and `make test-integration` run under the race detector, as CI does. CI
enforces coverage floors (unit ≥ 20%, integration ≥ 50%). `make lint` needs
[golangci-lint](https://golangci-lint.run/) v2 (CI pins v2.14.0; `.golangci.yml` is in
the v2 format, which a v1 install cannot read).

For database-backed changes, run the integration suite against local Postgres:

```bash
make postgres-up
make test-integration
```

Use `make postgres-down` when you are done, or `make postgres-reset` if you need a clean database volume.

## Pull Requests

`main` is protected: **all** changes (including releases) land via a pull request —
direct pushes are rejected — and every CI check must pass on a branch that is up to
date with `main` before a PR can merge: `Unit Tests`, `Integration Tests`, `Go Checks`,
`govulncheck`, `gosec` and `check-branch-name`. PRs are squash-merged.

- **Branch naming is CI-enforced** ([`.github/workflows/branch-naming.yml`](.github/workflows/branch-naming.yml)).
  Branches must match `(feature|fix|bugfix|hotfix|docs|chore|refactor)/<lowercase-with-dashes>`
  (e.g. `feature/add-mcp-support`, `fix/cache-warning`). `main` is allowed and
  `dependabot/*` is exempt; `release/*` is **not** an allowed name (releases use a
  `chore/` branch — see [docs/RELEASING.md](docs/RELEASING.md)).
- Keep changes focused and describe the behavior being changed.
- Add or update tests for bug fixes, migrations, and public API behavior.
- Update `README.md`, `docs/`, or migration docs when configuration, schema, or setup changes.
- Never edit a migration that has shipped in a release: change the schema with a new
  numbered `.up.sql`/`.down.sql` pair in `migrations/`, pin its SHA-256 in
  `migrations_test.go`, and list it in [docs/migrations.md](docs/migrations.md). An
  unreleased migration may still change, together with its pinned checksum.
- Do not include secrets, private keys, or production credentials in examples or tests.

## Releasing

Maintainers: see [docs/RELEASING.md](docs/RELEASING.md) for the release process
(the per-release checklist, how tags are created and protected, and SemVer guidance).

## Conduct

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Please do not report security vulnerabilities in public issues. Follow the process in [SECURITY.md](SECURITY.md).
