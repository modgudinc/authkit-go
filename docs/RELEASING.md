# Releasing

This project publishes **signed, immutable** release tags. A tag's signature is
part of the tag object, so it must be created signed the first time — and because
tags are immutable, **a published tag cannot be changed or deleted**. If a tag
goes out wrong, you cannot fix it; you must supersede it with a new version.

Versions follow [Semantic Versioning](https://semver.org/). While the library is
pre-1.0 (`0.x`): a **breaking** change is a **minor** bump (`0.x.0`), a
backward-compatible change is a **patch** (`0.x.y`).

## One-time setup (per maintainer machine)

Signing uses **SSH** (gpg is intentionally not required).

1. Use git ≥ 2.34: `git --version`.
2. Configure SSH signing:
   ```bash
   git config --global gpg.format ssh
   git config --global user.signingkey ~/.ssh/<your-signing-key>.pub
   git config --global commit.gpgsign true   # sign commits
   git config --global tag.gpgsign true       # auto-sign tags (so you can't forget)
   ```
3. **Register that public key on GitHub as a _Signing Key_** (Settings → SSH and
   GPG keys → New SSH key → Key type: **Signing Key**). This is separate from an
   auth key — without it GitHub marks the signature "Unverified" and the
   require-signed-tags ruleset rejects the push.
4. Ensure the key is loaded in the agent (`ssh-add -l`) so signing is non-interactive.
5. *(Optional, for local `git tag -v`)* configure an allowed-signers file:
   ```bash
   mkdir -p ~/.config/git
   echo "<your-email> $(cat ~/.ssh/<your-signing-key>.pub)" >> ~/.config/git/allowed_signers
   git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
   ```

Quick readiness check:

```bash
git config --get gpg.format        # -> ssh
git config --get user.signingkey   # -> path to your .pub
ssh-add -l                         # signing key present
```

## Repository protections

Two independent rulesets shape the flow below:

- **`main` is protected:** all changes land via a **pull request** (direct
  `git push origin main` is rejected), and the **`gosec` status check must pass**
  before merge. So releases are cut from `main` *after* a release PR merges — there
  are no long-lived `release/*` branches (and `release/*` is not even an allowed
  branch name; see [CONTRIBUTING.md](../CONTRIBUTING.md)).
- **Tags must be signed** (require-signed-tags ruleset). Tag refs are **not**
  branch-rule-gated, so a signed tag is pushed directly once `main` has the release
  commit.

## Per-release checklist

1. **`main` is green and ready.**
   ```bash
   make lint
   make test
   make postgres-up && make test-integration && make postgres-down
   ```
   (`gosec` and `govulncheck` also run in CI via `.github/workflows/security.yml`;
   `gosec` is a required merge gate.)

2. **Update `CHANGELOG.md`.** Move the `[Unreleased]` items into a new
   `## [X.Y.Z] - YYYY-MM-DD` section (the date is the day the tag is cut), flag any
   breaking change, and update any compare/tag links. Choose `X.Y.Z` per SemVer (see above).

3. **Write release notes:** `docs/releases/RELEASE_NOTES_vX.Y.Z.md` (follow the
   existing files — highlights, breaking changes, security, upgrade notes).

4. **Open a release PR** from a conventionally-named branch (a `release/*` branch is
   NOT allowed — use a `chore/` branch; the commit is signed via the one-time setup):
   ```bash
   git switch -c chore/release-X-Y-Z          # dashes, not dots (branch-naming rule)
   git add CHANGELOG.md docs/releases/RELEASE_NOTES_vX.Y.Z.md
   git commit -m "Release vX.Y.Z"
   git push -u origin chore/release-X-Y-Z
   gh pr create --base main --title "Release vX.Y.Z" --body-file docs/releases/RELEASE_NOTES_vX.Y.Z.md
   ```

5. **Merge the PR** once CI is green (the required `gosec` check must pass). Use a
   merge or squash merge per repo preference; the result is the release commit on `main`.

6. **Sync `main`, then create the signed tag on the merged release commit and verify
   BEFORE pushing** (the push is irreversible — the tag is immutable):
   ```bash
   git switch main && git pull --ff-only
   git tag -s vX.Y.Z -m "authkit-go vX.Y.Z"
   git cat-file -p vX.Y.Z | grep -q "BEGIN SSH SIGNATURE" && echo "signed ✓"
   ```
   Do NOT create/push the tag before the PR merges — a tag pushed early points at a
   commit that isn't on `main` and would have to be deleted and recreated.

7. **Push the tag** (tag refs are not branch-rule-gated):
   ```bash
   git push origin vX.Y.Z
   ```

8. **Publish the GitHub Release** from the existing tag:
   ```bash
   gh release create vX.Y.Z \
     --title "authkit-go vX.Y.Z" \
     --notes-file docs/releases/RELEASE_NOTES_vX.Y.Z.md \
     --verify-tag
     # add --prerelease while in 0.x, if desired
   ```
   `--verify-tag` makes `gh` use your signed tag instead of creating a new one.

9. **Verify:** the tag shows **Verified** on GitHub, and
   `go get github.com/modgudinc/authkit-go@vX.Y.Z` resolves.

## Alternative: let GitHub create the tag

A tag created through the GitHub web UI ("Draft a new release") — or by
`gh release create vX.Y.Z` when the tag does not yet exist — is created
server-side and signed by GitHub's web-flow key, which also satisfies the
require-signed-tags ruleset. Use this if you prefer not to sign locally; the
trade-off is that GitHub (not you) is the recorded signer. Pick one convention
and stick to it.

## If a tag goes out wrong

Tags are immutable: you cannot move, re-sign, or delete `vX.Y.Z` once pushed.
Ship the fix as the next version (e.g. a `vX.Y.(Z+1)` patch) created correctly.
