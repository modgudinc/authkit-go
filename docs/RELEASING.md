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

## Per-release checklist

1. **Green `main`.**
   ```bash
   make lint
   make test
   make postgres-up && make test-integration && make postgres-down
   ```
   (`gosec` and `govulncheck` also run in CI via `.github/workflows/security.yml`.)

2. **Update `CHANGELOG.md`.** Move the `[Unreleased]` items into a new
   `## [X.Y.Z] - YYYY-MM-DD` section, flag any breaking change, and update the
   compare/tag links at the bottom of the file. Choose `X.Y.Z` per SemVer (see above).

3. **Write release notes:** `docs/releases/RELEASE_NOTES_vX.Y.Z.md` (follow the
   existing files — highlights, breaking changes, security, upgrade notes).

4. **Commit and push** the changelog + notes to `main` (commit is signed via the
   one-time setup):
   ```bash
   git add CHANGELOG.md docs/releases/RELEASE_NOTES_vX.Y.Z.md
   git commit -m "Release vX.Y.Z"
   git push origin main
   ```

5. **Create the signed tag on the release commit, and verify BEFORE pushing**
   (the push is irreversible — the tag is immutable):
   ```bash
   git tag -s vX.Y.Z -m "authkit-go vX.Y.Z"
   git cat-file -p vX.Y.Z | grep -q "BEGIN SSH SIGNATURE" && echo "signed ✓"
   ```

6. **Push the tag:**
   ```bash
   git push origin vX.Y.Z
   ```

7. **Publish the GitHub Release** from the existing tag:
   ```bash
   gh release create vX.Y.Z \
     --title "authkit-go vX.Y.Z" \
     --notes-file docs/releases/RELEASE_NOTES_vX.Y.Z.md \
     --verify-tag
     # add --prerelease while in 0.x, if desired
   ```
   `--verify-tag` makes `gh` use your signed tag instead of creating a new one.

8. **Verify:** the tag shows **Verified** on GitHub, and
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
