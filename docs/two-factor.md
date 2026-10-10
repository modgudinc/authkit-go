# Two-factor sign-in

With `Config.TwoFactorConfig` set, people can add an authenticator app (Google
Authenticator, 1Password, Authy and the like) to their account. From then on a
password login needs a code from the app too, or one of ten single-use recovery
codes. authkit keeps the app's secret encrypted and the recovery codes hashed,
checks the codes, and holds the login until the second factor arrives.

The codes are TOTP (RFC 6238) as authenticator apps implement it: HMAC-SHA1, six
digits, a new code every 30 seconds. A code is accepted during its own 30 seconds
and the 30 seconds either side, to allow for a slow clock and slow typing, and only
once.

## Turning it on

1. Apply migration `000009_two_factor`. It only adds tables, so it is safe while
   older code runs. See [migrations.md](migrations.md).
2. Make a key of its own (not `SecretConfig.EncryptionKey`):

   ```bash
   openssl rand -base64 32
   ```

3. Deploy with it, and the name people will see in their app:

```go
kit, err := authkit.New(authkit.Config{
    // ...
    TwoFactorConfig: authkit.TwoFactorConfig{
        EncryptionKey: os.Getenv("TWO_FACTOR_ENCRYPTION_KEY"),
        Issuer:        "Acme",
    },
})
```

Apply the migration first: with the key set, every password login reads the new
tables. authkit derives two keys from the one you give it, one that encrypts the
apps' secrets (AES-256-GCM) and one that recovery codes are hashed under
(HMAC-SHA256). Keep it like any other key. If it is lost or changed, people with
two-factor on cannot finish a password login until it is turned off for them.

Without the key, nobody is asked for a second factor, even people who set one up,
and every `TwoFactorService` call returns `ErrTwoFactorNotConfigured`. Removing the
key therefore turns two-factor off for everyone.

## Setting up an app

A signed-in person asks to turn two-factor on. `EnrollTOTP` makes a new secret,
stores it encrypted but not yet active, and returns it. Show `URI` as a QR code for
the app to scan, and `Secret` for people who type it in. authkit does not draw QR
codes; a library such as `github.com/skip2/go-qrcode` makes the image.

```go
// startTwoFactor makes a new secret for the signed-in person to add to their app.
func startTwoFactor(kit *authkit.AuthKit) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        enrollment, err := kit.TwoFactorService().EnrollTOTP(r.Context(), signedInUserID(r))
        if err != nil {
            writeError(w, err)
            return
        }
        writeJSON(w, http.StatusOK, enrollment) // {"secret": "...", "uri": "otpauth://totp/Acme:..."}
    }
}
```

`signedInUserID` stands for however your application reads the user from its access
token. The URI names the account by the user's email, after the issuer.

Nothing changes until the person proves the app works by entering its first code.
`ConfirmTOTP` turns two-factor on and returns their recovery codes:

```go
// confirmTwoFactor turns two-factor on with the first code from the app, and
// returns the recovery codes to show once.
func confirmTwoFactor(kit *authkit.AuthKit) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var req struct {
            Code string `json:"code"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "bad request", http.StatusBadRequest)
            return
        }
        codes, err := kit.TwoFactorService().ConfirmTOTP(r.Context(), signedInUserID(r), req.Code)
        if err != nil {
            writeError(w, err)
            return
        }
        writeJSON(w, http.StatusOK, map[string][]string{"recovery_codes": codes})
    }
}
```

Recovery codes look like `k7qd-3mxa-wp2c-h6ze`. Show them once and tell the person
to keep them somewhere safe: authkit keeps only their hashes. Each signs in once in
place of a code, for when the phone is lost. People can type them in either case,
with or without the dashes.

Calling `EnrollTOTP` again before confirming replaces the secret, so a person who
scanned the wrong code can start over. Once two-factor is on, `EnrollTOTP` and
`ConfirmTOTP` return `ErrTwoFactorAlreadyEnabled`; turn it off first to move to a
new phone.

## Signing in

For a person with two-factor on, `Login`, `LoginByEmail` and their
`WithInstallation` forms check the password as before and then stop: no session, no
tokens. They return an error that unwraps to `ErrSecondFactorRequired` and carries a
challenge. Send the challenge to the client, ask for a code, and finish the login
with `CompleteSecondFactor`:

```go
// login signs a person in with their password. When they have two-factor on, it
// answers with the challenge for the code step instead of tokens.
func login(kit *authkit.AuthKit) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var req struct {
            Email    string `json:"email"`
            Password string `json:"password"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "bad request", http.StatusBadRequest)
            return
        }
        resp, err := kit.AuthService().LoginByEmail(r.Context(), model.LoginByEmailRequest{
            Email:       req.Email,
            Password:    req.Password,
            SessionInfo: &model.SessionInfo{IPAddress: r.RemoteAddr, UserAgent: r.UserAgent()},
        })
        var second *model.SecondFactorRequiredError
        switch {
        case errors.As(err, &second):
            writeJSON(w, http.StatusOK, map[string]any{
                "second_factor_required": true,
                "challenge":              second.Challenge,
                "expires_at":             second.ExpiresAt,
            })
        case err != nil:
            writeError(w, err)
        default:
            writeJSON(w, http.StatusOK, resp)
        }
    }
}

// secondFactor finishes a login with a code from the person's app or a recovery
// code.
func secondFactor(kit *authkit.AuthKit) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var req model.CompleteSecondFactorRequest // {"challenge": "...", "code": "123456"}
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "bad request", http.StatusBadRequest)
            return
        }
        resp, err := kit.TwoFactorService().CompleteSecondFactor(r.Context(), req)
        if err != nil {
            writeError(w, err)
            return
        }
        writeJSON(w, http.StatusOK, resp.LoginResponse)
    }
}
```

`CompleteSecondFactor` does what the login would have done: the same workspace
selection, the same installation binding (it returns the `Session` when there is
one), the same `SessionInfo` and the same sign-in history. Its response is the
login's, so the client handles it as it would a login without two-factor.

The challenge:

- is good for five minutes and one finished login. A second call with it, even with
  a good code, is `ErrInvalidCredentials`.
- survives a wrong code (`ErrInvalidSecondFactor`), so the person can try again
  without the password. Each wrong code counts toward the account lockout below.
- is a secret: whoever holds it can finish the login with a code. Keep it in the
  client's memory, not in a URL. authkit stores only its SHA-256.
- ends when it expires, when the person turns two-factor off, changes their
  password or signs out everywhere, or when the account is deleted. An unknown,
  expired or finished challenge is `ErrInvalidCredentials`; send the person back to
  the password step.

Telling the client that a second factor is needed tells it the password was right.
That is the same as any two-step login; the lockout and your rate limiter bound what
it is worth.

### The lockout

A wrong code counts toward the same failed-login lockout as a wrong password
(`MaxFailedLoginAttempts`, five, then `LockDuration`, 30 minutes). The count is
reset only when a whole sign-in succeeds. A right password alone does not reset it
for a person with two-factor on, so knowing the password does not buy more guesses
at the code. Once the account is locked, `CompleteSecondFactor` returns
`ErrAccountLocked`, and a disabled account `ErrAccountDisabled`: the caller has
already shown the password, so there is nothing to hide.

With `Config.RateLimiter` set, `CompleteSecondFactor` asks it first, with the key
`second_factor:<userID>`.

### Other sign-ins

`VerifiedLoginService.OpenSession` never asks for a second factor: the application
verified the person itself. A passkey with user verification is already two factors.
For a sign-in with a provider, such as Google, the provider's own two-factor
applies. To ask for the code before `OpenSession` too, for an emailed code say, call
`TwoFactorService.Verify` first.

## Checking a code for a signed-in person

`Verify` checks a code, or spends a recovery code, for someone already signed in:
before turning two-factor off, changing the email or password, or anything else you
want to protect from a borrowed laptop. A wrong code counts toward the lockout. It
returns `ErrNotFound` when the person has two-factor off.

```go
// stopTwoFactor turns two-factor off once the person shows they still hold it.
func stopTwoFactor(kit *authkit.AuthKit) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var req struct {
            Code string `json:"code"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "bad request", http.StatusBadRequest)
            return
        }
        userID := signedInUserID(r)
        if err := kit.TwoFactorService().Verify(r.Context(), userID, req.Code); err != nil {
            writeError(w, err)
            return
        }
        if err := kit.TwoFactorService().Disable(r.Context(), userID); err != nil {
            writeError(w, err)
            return
        }
        w.WriteHeader(http.StatusNoContent)
    }
}
```

## Managing it

```go
status, err := kit.TwoFactorService().Status(ctx, userID)               // Enabled, EnabledAt, RecoveryCodesLeft
codes, err := kit.TwoFactorService().RegenerateRecoveryCodes(ctx, userID) // the old ones stop working
err = kit.TwoFactorService().Disable(ctx, userID)                        // deletes the secret, codes and waiting logins
n, err := kit.TwoFactorService().CleanupExpired(ctx)                     // run periodically
```

Authorize the caller before passing a `userID`: a person manages their own
two-factor, and an administrator whoever your policy allows. A person who lost both
their phone and their recovery codes needs someone to call `Disable` for them once
your support process has confirmed who they are; that is the recovery path, so guard
it as carefully as a password reset.

`Status` reads the replica, so it suits a settings page. Logins and code checks read
the primary.

`CleanupExpired` deletes logins that waited past their five minutes. A new login
also drops the same person's expired ones, so the table stays small without it, but
run it from the same job as `SignInHistoryService.Cleanup` and
`SessionService.CleanupExpired`.

## What is stored

| Table | Holds |
|---|---|
| `totp_factors` | One row per user: the app's secret, encrypted and bound to the user, when it was confirmed, and the last 30-second step a code was accepted for |
| `recovery_codes` | The user's recovery codes as HMAC-SHA256 hashes, and when each was used |
| `second_factor_challenges` | Logins waiting for a code: the SHA-256 of the challenge, the user, what the login asked for (call, workspace, installation, `SessionInfo`) and when it expires |

All three cascade when the user row is deleted. A secret copied to another user's
row does not decrypt.

## In the history and metrics

A wrong code during a login is recorded in the sign-in history
([sign-in-history.md](sign-in-history.md)) as a refusal with reason
`bad_second_factor`, and counted as `authkit_login_failure_total{reason="bad_second_factor"}`.
The finished login is recorded as a `password` sign-in, with the session it opened.
A password step that is waiting for its code records nothing.

## Errors

| Error | When | HTTP |
|---|---|---|
| `ErrSecondFactorRequired` | A password login of a person with two-factor on; the error is a `*model.SecondFactorRequiredError` with the challenge | Your choice; the example answers 200 |
| `ErrInvalidSecondFactor` | A wrong, reused or out-of-date code, or a recovery code already spent; the challenge stays usable | 401 |
| `ErrInvalidCredentials` | `CompleteSecondFactor` with an unknown, expired or finished challenge | 401 |
| `ErrAccountLocked`, `ErrAccountDisabled` | `CompleteSecondFactor` for an account locked or disabled since the password step | 403 |
| `ErrTwoFactorAlreadyEnabled` | `EnrollTOTP` or `ConfirmTOTP` when two-factor is already on | 409 |
| `ErrTwoFactorNotConfigured` | Any `TwoFactorService` call without `Config.TwoFactorConfig` | 500 |
| `ErrNotFound` | `ConfirmTOTP` with nothing enrolled; `Verify`, `Disable` or `RegenerateRecoveryCodes` with two-factor off; an unknown user | 404 |

Database faults are `ErrInternal`, including a missing migration, and so is a
secret that does not decrypt because the key changed.

## Not included

- SMS or email codes as a second factor. Send an OTP with `OTPService` and check it
  in your own step if you need them.
- WebAuthn as a second factor after a password. Offer passkeys as a sign-in of their
  own instead ([passkeys.md](passkeys.md)).
- "Remember this device": every password login asks.
- A claim in the access token saying two factors were used.
