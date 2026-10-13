# Releasing

This project publishes **immutable** releases. Publishing a GitHub Release creates
its `vX.Y.Z` tag on `main`, and from then on neither the release nor its tag can be
changed or deleted. The Go module proxy caches a version the first time anyone asks
for it, so a published version is permanent there too. If a release goes out wrong,
you cannot fix it; you must supersede it with a new version.

Versions follow [Semantic Versioning](https://semver.org/). While the library is
pre-1.0 (`0.x`): a **breaking** change is a **minor** bump (`0.x.0`), a
backward-compatible change is a **patch** (`0.x.y`).

## Repository protections

Three settings shape the flow below:

- **`main` is protected** (`merge-to-main` ruleset): all changes land via a
  **pull request** (direct `git push origin main` is rejected), PRs are squash-merged,
  and every CI check must pass on a branch that is up to date with `main`. So
  releases are cut from `main` *after* a release PR merges; there are no long-lived
  `release/*` branches (and `release/*` is not even an allowed branch name; see
  [CONTRIBUTING.md](../CONTRIBUTING.md)).
- **Release tags are protected** (`release-tags` ruleset on `refs/tags/v*`): only
  repository admins can create, move or delete a `v*` tag.
- **Releases are immutable** (repository setting): once a release is published, its
  tag and assets are locked.

## Per-release checklist

1. **`main` is green and ready.**
   ```bash
   make lint
   make test
   make postgres-up && make test-integration && make postgres-down
   ```
   (`gosec` and `govulncheck` also run in CI via `.github/workflows/security.yml`.)

2. **Update `CHANGELOG.md`.** Move the `[Unreleased]` items into a new
   `## [X.Y.Z] - YYYY-MM-DD` section (the date is the day the release is published),
   flag any breaking change, and update any compare/tag links. Choose `X.Y.Z` per
   SemVer (see above).

3. **Write release notes:** `docs/releases/RELEASE_NOTES_vX.Y.Z.md` (follow the
   existing files — highlights, breaking changes, security, upgrade notes).

4. **Open a release PR** from a conventionally-named branch (a `release/*` branch is
   NOT allowed — use a `chore/` branch):
   ```bash
   git switch -c chore/release-X-Y-Z          # dashes, not dots (branch-naming rule)
   git add CHANGELOG.md docs/releases/RELEASE_NOTES_vX.Y.Z.md
   git commit -m "Release vX.Y.Z"
   git push -u origin chore/release-X-Y-Z
   gh pr create --base main --title "Release vX.Y.Z" --body-file docs/releases/RELEASE_NOTES_vX.Y.Z.md
   ```

5. **Squash-merge the PR** once CI is green. The squash commit is the release commit
   on `main`, signed by GitHub.

6. **Publish the GitHub Release**, which creates the tag on the release commit. Check
   that `main`'s head is the release commit first, then:
   ```bash
   gh release create vX.Y.Z \
     --target main \
     --title "authkit-go vX.Y.Z" \
     --notes-file docs/releases/RELEASE_NOTES_vX.Y.Z.md
   ```
   (or "Draft a new release" in the web UI, with a new `vX.Y.Z` tag on `main`). Do
   NOT publish before the PR merges: the tag would point at a commit that isn't the
   release commit, and it cannot be moved afterwards.

7. **Verify:** the release shows as immutable on GitHub, and
   `go get github.com/modgudinc/authkit-go@vX.Y.Z` resolves.

## If a release goes out wrong

Releases and their tags are immutable: you cannot move or delete `vX.Y.Z` once it
is published. Ship the fix as the next version (e.g. a `vX.Y.(Z+1)` patch), and if
the bad version must not be used, add a `retract` directive for it to `go.mod` in that
release.
