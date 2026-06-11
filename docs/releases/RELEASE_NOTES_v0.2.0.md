# authkit-go v0.2.0

A security-hardening follow-up to [v0.1.0](RELEASE_NOTES_v0.1.0.md). Small, focused changes plus **one breaking change** (removal of `Repository.VerifyCode`).

```bash
go get github.com/modgudinc/authkit-go@v0.2.0
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## ⚠️ Breaking changes

- **`Repository.VerifyCode` removed.** It was a read-only OTP check that did **not** consume the code, count failed attempts, or scope by purpose — an auth footgun if called directly. Use `ConsumeVerificationCode` (via `OTPService.Validate`) for the verification path, which is single-use, attempt-limited, tenant- and purpose-scoped, and constant-time.

## Security

- **Role changes invalidate stale access tokens.** `UserService.Update` / `UpdateRolesByTenant` (and the underlying `UpdateByTenant` / `UpdateRolesByTenant`) now bump the user's `token_version`. Because roles are embedded in access-token claims, a role downgrade now takes effect immediately: outstanding access tokens are rejected by `ValidateJWT`, and the next refresh re-issues correctly-scoped tokens (the user is **not** logged out).
- **`TokenService.ValidateRefreshToken` now rejects disabled/locked accounts.** It previously returned the user without an account-status check, unlike the rotation path. It now applies the same gate, so it is safe even if a consumer calls it directly to build a session. (The recommended path remains `AuthService.RefreshToken` → `RefreshTokenPair`.)

## Documentation

- **`AcceptInvitation` is now the documented signup path** in the README and `docs/examples.md`. The manual `ValidateInvitation` → create-user → `IncrementUseCount` sequence is now marked as a lower-level building block with an explicit TOCTOU / over-redemption warning. `AcceptInvitation` validates, consumes, and creates the user in a single transaction.

## Upgrading from 0.1.0

- **Replace any `repo.VerifyCode(...)` calls.** For auth, switch to `OTPService.Validate(ctx, tenantID, email, code, purpose)`. If you only need an existence check, query the verification code yourself; do not reintroduce a non-consuming check in an auth flow.
- **Expect access tokens to be invalidated on role edits.** After `Update`/`UpdateRolesByTenant`, a client's current access token will fail `ValidateJWT` (`ErrTokenRevoked`) and must refresh. This is intentional; the refresh token stays valid, so the next refresh is seamless.
- **`ValidateRefreshToken` is now stricter** — it returns `ErrInvalidRefreshToken` for disabled/locked accounts. If you relied on it returning a user regardless of status, gate on account status in your own code or use it as intended.

## Verification

`gofmt`, `go vet` (default + `integration`), `golangci-lint`, and `gosec` are clean; unit and PostgreSQL integration tests pass, with coverage enforced at ≥ 30% in CI.

---

Full changes: see [CHANGELOG.md](../../CHANGELOG.md). Licensed under [Apache-2.0](../../LICENSE).
