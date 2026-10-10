# Sign-in history

With `Config.RecordSignIns` set, authkit records every sign-in attempt on an existing
account: who, how, into which workspace, from where, and whether it worked. An
application can show a person their recent sign-ins ("was this you?"), and an
administrator can see why someone cannot get in or what an attacker tried.

## Turning it on

1. Apply migration `000007_sign_in_events`. It only adds a table, so it is safe while
   older code runs. See [migrations.md](migrations.md).
2. Deploy with `RecordSignIns: true`:

```go
kit, err := authkit.New(authkit.Config{
    // ...
    RecordSignIns: true,
})
```

It is off by default. Code without it never writes to the table.

## What is recorded

One row per attempt, from these calls:

| Call | Method | Recorded |
|---|---|---|
| `Login`, `LoginByEmail` and their `WithInstallation` forms | `password` | Success, or a refusal of an existing account |
| `TwoFactorService.CompleteSecondFactor` | `password` | The login's success, or a wrong code ([two-factor.md](two-factor.md)) |
| `VerifiedLoginService.OpenSession` | The method the application passed (`google`, `email_link`, ...) | Success, or a refusal of the account |

A refusal carries its reason:

| Reason | Meaning |
|---|---|
| `bad_password` | Wrong password (it also counts toward the lockout) |
| `no_password` | Password login to an account that signs in only through `OpenSession` |
| `account_disabled` | The account is disabled |
| `account_locked` | The account is locked |
| `no_membership` | The account checked out, but has no active membership in the workspace asked for |
| `bad_second_factor` | The password was right, but the two-factor code was wrong or already used (it also counts toward the lockout); see [two-factor.md](two-factor.md) |

The caller of `Login` still gets `ErrInvalidCredentials` for the first four, so
nobody learns from the response whether an account exists or is locked; the reason is
for the history only. The same names label `authkit_login_failure_total`.

Recording a refusal adds one insert to that response, as the lockout counter already
does for a wrong password. So with the history on, a disabled, locked or passwordless
account answers in about the time any other existing account does, rather than in the
time an unknown email does. The bcrypt comparison every attempt pays dominates both.

Not recorded:

- Attempts on an email that matches no account. There is no account to attach them
  to; the logger and `authkit_login_failure_total{reason="not_found"}` still see them.
- Attempts the `RateLimiter` refuses, which never reach an account.
- Refreshes and workspace switches (`RefreshToken`, `MintWorkspaceToken`). They
  continue a sign-in rather than start one.
- Sign-ins that fail inside authkit (a database error), which return `ErrInternal`.

Each row (`model.SignInEvent`) also has:

- `TenantID`: the workspace the sign-in asked for or selected, or `""` when the person
  signed in without choosing one (`LoginByEmail` with several workspaces).
- `SessionID` and `InstallationID`: the session record a success opened, if any
  (`OpenSession` opens one whenever session support is on, a password login only with
  an installation), and the installation the sign-in was bound to.
- `Namespace`: the `SessionConfig.Namespace` of the application signed in to.
- `IPAddress`, `UserAgent`, `DeviceName`: from the request's `SessionInfo`.

The client sends the user agent and device name, and failed attempts are recorded
before anyone has signed in, so authkit stores them defensively: the user agent is cut
to 512 bytes, NUL bytes and invalid UTF-8 are dropped, and an address that does not
parse is left out. `IPAddress` may be an `http.Request`'s `RemoteAddr` (`host:port`); the
host is kept. Set it from your proxy's trusted client address rather than a raw
`X-Forwarded-For` list, which does not parse and is left out.

## Reading it

```go
events, err := kit.SignInHistoryService().List(ctx, userID, 20, 0) // newest first
for _, e := range events {
    if !e.Succeeded {
        fmt.Println(e.OccurredAt, e.Method, "refused:", e.FailureReason, "from", e.IPAddress)
    }
}
```

`List` takes a page size of 1 to 200 and an offset. It covers every application that
shares the identity database, since an account's sign-ins elsewhere matter to its
security; filter on `Namespace` to show one application's. Authorize the caller before
passing a `userID`, as for `SessionService`: a person may read their own history, and
an administrator whoever your policy allows.

## Keeping it bounded

The history grows with every attempt, and failed attempts against a known email can be
made by anyone. Rate-limit sign-ins (`Config.RateLimiter`, see SECURITY.md) and prune
the history on a schedule:

```go
removed, err := kit.SignInHistoryService().Cleanup(ctx, 90*24*time.Hour)
```

IP addresses and user agents are personal data in many jurisdictions; pick the
retention period your privacy policy states. Deleting a user's row (not
`UserService.Delete`, which only disables the account) deletes their history.

## When a row cannot be written

Recording is best-effort, like `last_login`: a sign-in succeeds or fails on its own
merits whether or not its row is written. A failed write is logged at error level and
counted as `authkit_best_effort_write_failure_total{op="record_sign_in"}`; alert on it.
A missing migration shows up there first. The row is written even if the client hangs
up after the outcome is decided.
