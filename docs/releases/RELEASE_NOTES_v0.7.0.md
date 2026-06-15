# authkit-go v0.7.0

An API-ergonomics release. The headline: **you can now name the service types you
get back**. Secondary: user IDs and timestamps have a single representation each
at the API boundary. Breaking at the Go-type level (acceptable pre-1.0), but the
JSON wire format is unchanged and there is no schema change.

```bash
go get github.com/modgudinc/authkit-go@v0.7.0
```

> **Pre-1.0:** the public API may change in minor (`0.x`) releases. Pin a version.

## Highlights

- **Nameable service interfaces.** Every accessor (`AuthService()`,
  `UserService()`, …) now returns a named interface from package `authkit`. You
  can store one on a struct field, pass it to a function, or mock it in a test:

  ```go
  type Handlers struct {
      auth authkit.AuthService // previously impossible to name
  }
  h := Handlers{auth: identity.AuthService()}
  ```

  Previously the accessors returned `*service.AuthService` from an `internal`
  package, so callers could only call methods on the value inline — never declare
  its type.

- **One representation for user IDs.** `JWTClaims.UserID`,
  `ChangePasswordRequest.UserID`, and `RefreshResponse.UserID` are now `uuid.UUID`,
  and `AuthService.LogoutAll` / `TokenService.RevokeAllUserTokens` take `uuid.UUID`.
  This matches the `User` entity and all `UserService` methods, so the
  string⇄UUID juggling at call sites is gone.

- **One representation for timestamps.** API-key and secret response timestamps are
  `time.Time` / `*time.Time` instead of pre-formatted RFC3339 strings, so you can
  do time math without re-parsing.

## Breaking changes (Go types only)

| Change | Before | After |
|--------|--------|-------|
| Service accessors | return `*service.X` (unnameable) | return `authkit.X` interface |
| `JWTClaims.UserID`, `ChangePasswordRequest.UserID`, `RefreshResponse.UserID` | `string` | `uuid.UUID` |
| `AuthService.LogoutAll`, `TokenService.RevokeAllUserTokens` | `userID string` | `userID uuid.UUID` |
| `CreateAPIKeyResponse.CreatedAt` / `ExpiresAt` | `string` / `*string` | `time.Time` / `*time.Time` |
| `SaveSecretResponse.CreatedAt` / `UpdatedAt` / `CreatedBy` | `string` / `string` / `string` | `time.Time` / `time.Time` / `uuid.UUID` |

**The JSON wire format does not change** — `uuid.UUID` marshals to the same UUID
string and `time.Time` to the same RFC3339 timestamp. Only the Go types you handle
in code change.

`CreateAPIKeyRequest.ExpiresIn` deliberately stays `*string`: it accepts calendar
units (`"6M"`, `"1y"`) that `time.Duration` cannot express.

## Security / dependencies

- **`golang.org/x/crypto` bumped to v0.52.0**, clearing the `crypto/ssh`
  advisories (including a critical SSH auth-bypass) reported by Dependabot.
  authkit-go uses only `golang.org/x/crypto/bcrypt`, so `govulncheck` reports **0**
  affected call paths — the bump is hygiene, not a fix for an exploitable issue.
- **Minimum Go is now 1.25** (required by `golang.org/x/crypto` v0.52.0).
- The remaining advisories `govulncheck` lists are Go standard-library ones; build
  with **Go 1.25.10+ / 1.25.11+** to clear them (a toolchain/CI choice, not a
  module change).

## Upgrading

- If you stored a service in a typed variable, you couldn't before (the type was
  internal); now use the `authkit.*Service` interface type.
- Where you converted a user ID to/from a string to call `LogoutAll`,
  `RevokeAllUserTokens`, `ChangePassword`, or to read `JWTClaims.UserID` /
  `RefreshResponse.UserID`, pass/read a `uuid.UUID` directly (drop the
  `.String()` / `uuid.Parse`).
- Where you read a response timestamp as a string, it's now a `time.Time`
  (call `.Format(time.RFC3339)` if you still want the string).

## Verification

`gofmt`, `go vet` (default + `integration`), and `golangci-lint` are clean; unit
and PostgreSQL integration tests pass, including the JWT generate→validate
round-trip with the `uuid.UUID` claim and the full login/refresh/logout-all flow.

---

Full changes: see [CHANGELOG.md](../../CHANGELOG.md). Licensed under [Apache-2.0](../../LICENSE).
