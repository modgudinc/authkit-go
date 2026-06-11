# Contributing

Thanks for your interest in improving authkit-go.

## Development

Run the unit test suite before opening a pull request:

```bash
make lint
make test
```

For database-backed changes, run the integration suite against local Postgres:

```bash
make postgres-up
make test-integration
```

Use `make postgres-down` when you are done, or `make postgres-reset` if you need a clean database volume.

## Pull Requests

- Keep changes focused and describe the behavior being changed.
- Add or update tests for bug fixes, migrations, and public API behavior.
- Update `README.md`, `docs/`, or migration docs when configuration, schema, or setup changes.
- Do not include secrets, private keys, or production credentials in examples or tests.

## Releasing

Maintainers: see [docs/RELEASING.md](docs/RELEASING.md) for the signed-release
process (SSH tag signing, the per-release checklist, and SemVer guidance).

## Security

Please do not report security vulnerabilities in public issues. Follow the process in [SECURITY.md](SECURITY.md).
