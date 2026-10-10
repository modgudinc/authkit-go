# Verified sign-in and linked identities

authkit verifies passwords. Applications often verify people in other ways too:
an OAuth or OIDC provider (Google, GitHub, an enterprise issuer), a signed email
link, an OTP, a passkey, or a device code approved in a signed-in browser. Two
additive services let those sign-ins use authkit's sessions and users:

- `VerifiedLoginService.OpenSession` opens a session for a user the application
  has already verified, in every session mode, with or without an installation,
  and records how the person signed in.
- `ExternalIdentityService` links a provider account, identified by the provider
  plus the provider's stable user id, to one authkit user, and finds that user on
  the next sign-in.

For passkeys, `PasskeyService` also stores the credentials; see
[passkeys.md](passkeys.md).

authkit does not implement OAuth or OIDC and is not an authorization server.
Verify the provider's response with a client library such as
`golang.org/x/oauth2` and `github.com/coreos/go-oidc/v3`, then pass the result here.

## Migrations

| Migration | Needed for | Notes |
| --- | --- | --- |
| `000003_session_sign_in` | `OpenSession` with session support enabled (`SessionOptional` or `SessionRequired`) | Adds `sessions.sign_in_method` and allows sessions with no installation. Apply it before deploying this version: the session queries read the new column. Existing sessions read as `"password"`. |
| `000004_external_identities` | `ExternalIdentityService`, in any mode | Adds `external_identities`. Not needed if you only use `OpenSession`. |
| `000005_email_verification` | Every deployment | Adds `users.email_verified_at`. Apply it before deploying this version: every user query reads the new column. Existing users start unverified. |

All are additive and idempotent, and safe to apply while older code runs. Apps in
`SessionDisabled` mode need only `000005` for `OpenSession`, and `000004` as well for
linked identities. For a custom `IdentitySchema`, take the files from
`authkit.Migrations(schema)` ([migrations.md](migrations.md)).

Rolling `000003` back deletes sessions that have no installation (and their refresh
tokens), since the older schema cannot hold them.

## Open a session for a verified user

```go
login, err := kit.VerifiedLoginService().OpenSession(ctx, model.OpenSessionRequest{
    UserID:       verifiedUserID, // from your own verification, never from the request
    SignInMethod: "google",
    TenantID:     tenantID,       // optional, as for LoginByEmail
    SessionInfo:  &model.SessionInfo{DeviceName: "Firefox", IPAddress: ip, UserAgent: ua},
})
```

**OpenSession checks no credential.** Whoever controls `UserID` controls the
account, so it must come from your own completed verification: the user an ID
token resolved to, the owner of a consumed email-link token, the user who approved
a device code. Never pass a user id taken from a request body, query string or
header.

What it does check, like a login:

- The account gates: `ErrNotFound` for an unknown user, `ErrAccountDisabled` and
  `ErrAccountLocked` (an expired lock does not block). It reads the primary.
- Workspace selection, as `LoginByEmail`: `TenantID` when given (else
  `ErrNoActiveMembership`), or the only active membership. With none or several,
  the response has a refresh token and `Memberships` but no access token; mint one
  with `AuthService.MintWorkspaceToken`.
- Input: `SignInMethod` is lowercased and must be 1 to 64 of `[a-z0-9._:-]`,
  starting with a letter or digit (`ErrInvalidInput`). `"password"` is reserved for
  authkit's own password logins.

It does not consult `Config.RateLimiter`: throttle your verification step (the
OAuth callback, the OTP check, the device-code poll) instead.

What it opens depends on the session mode:

| Mode | Without `Installation` | With `Installation` |
| --- | --- | --- |
| `SessionDisabled` | A plain identity session. `Session` is nil and the method is only logged and counted. | `ErrSessionDisabled` |
| `SessionOptional`, `SessionRequired` | A session record with `InstallationID` empty and `SignInMethod` set. | A session bound to the installation, as `LoginWithInstallation` would make. |

Sessions opened this way refresh, switch workspace, log out and revoke exactly like
password sessions. Logout-all and password changes end them too, and a disabled or
locked account cannot use them. `SessionService.List` shows each session's
`SignInMethod`. `ValidateInstallationJWT` refuses a session with no installation
(`ErrSessionRequired`); use `AuthService.ValidateJWT` for browser sessions.

The response embeds `LoginResponse` and adds `Session`, like
`InstallationLoginResponse`.

Choose method names that describe the verification, such as `google`, `github`,
`oidc:acme`, `email_link`, `otp`, `passkey` or `device_code`. They appear in
session records, logs and the `authkit_verified_login_total{method}` counter, so
keep the set small and fixed; never put user input in one.

### Device code example

A CLI starts a device-code flow, and the person approves it in a browser where
they are already signed in. Your approval handler stores the approving user's id
(from the browser's validated access token) on the device-code record. When the
CLI polls with its device code:

```go
// record was looked up by the polled device code, is approved, and is consumed here.
login, err := kit.VerifiedLoginService().OpenSession(ctx, model.OpenSessionRequest{
    UserID:       record.ApprovedByUserID,
    SignInMethod: "device_code",
    Installation: &model.InstallationBinding{InstallationID: record.InstallationID},
})
```

## Users without a password

A user may have no password: leave `PasswordHash` empty in
`UserService.Create` or `InvitationService.Accept`, or let `Resolve` create the
user. `User.HasPassword` reports it.

- Password login for such a user fails with `ErrInvalidCredentials` after a dummy
  bcrypt comparison, so it looks and takes as long as a wrong password. It does not
  count toward the failed-login lockout, so guesses cannot lock the owner out. The
  `authkit_login_failure_total` counter records `reason="no_password"`.
- `ChangePassword` returns `ErrIncorrectPassword`: there is no old password to
  match. To set a first password, verify the person yourself and call
  `UserService.SetPassword`, which ends their other sessions.
- Without a password, the email address is how the person gets back in, so record
  when they prove they own it ([Email verification](#email-verification)).

## Email verification

`User.EmailVerifiedAt` records when the user proved they own their email address;
nil means authkit doesn't know. `User.HasVerifiedEmail` reports it.

- Call `UserService.MarkEmailVerified(ctx, userID)` after the person proves it: they
  entered a code from `OTPService` that you sent to the address, or opened a signed
  link you sent there. Repeating it keeps the first time.
- `Resolve` sets it on the users it creates, because the provider verified the
  address.
- Accepting an invitation does not set it. Whoever created the invitation knows its
  code, so redeeming one proves nothing about the address.
- `UserService.Create` does not set it.

authkit does not require a verified email to sign in; that is your policy. It does
require one before `Resolve` links a provider sign-in to an existing account by
email (see [Linking rules](#linking-rules)).

## Sign in with an emailed code

`OTPService` and `OpenSession` together give passwordless sign-in by email, and the
same step verifies the address:

```go
// 1. Send a code. Do this whether or not an account exists for the address, so the
//    response does not reveal who has one. Config.RateLimiter and
//    OTPConfig.RateLimitDuration bound how often codes are sent.
otp, err := kit.OTPService().Generate(ctx, model.OTPGenerateRequest{
    Email: email, Purpose: "sign_in", ExpirationDuration: 10 * time.Minute,
})
// Email otp.Code to the address.

// 2. Check the code the person typed. It is used up, and a few wrong guesses
//    invalidate it.
if err := kit.OTPService().Validate(ctx, model.OTPValidateRequest{
    Email: email, Code: typedCode, Purpose: "sign_in",
}); err != nil {
    return err
}

// 3. The person owns the address. Find or create their user, and record it.
user, err := kit.UserService().GetByEmail(ctx, email)
userID := ""
switch {
case err == nil:
    userID = user.ID
case errors.Is(err, authkit.ErrNotFound):
    userID, err = kit.UserService().Create(ctx, model.CreateUserRequest{Email: email, DisplayName: name})
    if err != nil {
        return err
    }
default:
    return err
}
if err := kit.UserService().MarkEmailVerified(ctx, userID); err != nil {
    return err
}

// 4. Open the session.
login, err := kit.VerifiedLoginService().OpenSession(ctx, model.OpenSessionRequest{
    UserID: userID, SignInMethod: "email_code",
})
```

Because step 3 records the verification, a later Google sign-in for the same
address links to this account automatically, as long as it has no password.

## Linked sign-in identities

An identity is a provider name plus the provider's subject:

- `Provider` is your name for one provider configuration, lowercased: `google`,
  `github`, `oidc:acme`. Use a different name for each issuer.
- `Subject` is the provider's stable, case-sensitive user id: the OIDC `sub` claim,
  or GitHub's numeric user id. Never an email or a username, which can change or be
  reassigned.

The email a provider reports is stored on the link as a snapshot for display. It
never changes the user's own email.

### Resolve a provider sign-in

```go
res, err := kit.ExternalIdentityService().Resolve(ctx, model.ResolveExternalIdentityRequest{
    Provider:      "google",
    Subject:       idToken.Subject,
    Email:         claims.Email,
    EmailVerified: claims.EmailVerified,
    DisplayName:   claims.Name,
    CreateUser:    true, // sign-up allowed; false for sign-in only
})
switch {
case err == nil:
    // res.User signed in. res.Created: a new user; res.Linked: linked just now.
case errors.Is(err, authkit.ErrIdentityLinkRequired):
    // An account exists for this email but cannot be linked automatically.
    // See "When linking needs the owner" below.
case errors.Is(err, authkit.ErrEmailNotVerified):
    // Sign-up needs a verified email from the provider.
case errors.Is(err, authkit.ErrNotFound):
    // No account, and CreateUser was false.
}
```

`Resolve` does not open a session or check account status. Pass `res.User.ID` to
`OpenSession`, which refuses disabled and locked accounts.

### Linking rules

1. A returning sign-in is found by `(Provider, Subject)` alone, whatever email the
   provider reports now.
2. A first sign-in is linked to the user who owns its email only when all of these
   hold; otherwise `Resolve` returns `ErrIdentityLinkRequired` and changes nothing:
   - `EmailVerified` is true;
   - the user has proven they own the address too, so `User.EmailVerifiedAt` is
     set (`email_unverified`);
   - the user has no password (`has_password`);
   - the user has no other account at the same provider
     (`provider_account_mismatch`).
3. With no user for the email, `CreateUser` creates one without a password, with
   its email marked verified, and links it (a verified email is required, else
   `ErrEmailNotVerified`); without `CreateUser`, `ErrNotFound`.

An unverified email never finds a user, so it can neither link nor reveal an
account. Emails match case-insensitively.

Why each refusal:

- **The user's email is not verified.** Whoever created the account may not own
  the address: an admin who created it, or someone who redeemed an invitation they
  wrote. If it were linked, the address's real owner would sign in to an account
  its creator may still hold a session for (pre-account hijacking).
- **The user has a password.** Anyone could have created that account with
  someone else's address and a password of their choosing, then waited for the
  owner to sign in with Google (pre-account hijacking). The owner proves they hold
  the password before linking.
- **Another account at the same provider.** Providers can give an address to a new
  account, such as a recycled workplace email. The subject, not the email, says
  which account it is.

The `authkit_identity_link_refused_total{reason}` counter records each refusal.

### When linking needs the owner

Keep the verified provider identity in short-lived server-side state (never in a
client-controlled cookie or form field), ask the person to sign in to the existing
account the usual way, then link it:

```go
// userID comes from the session the person just opened with their password.
_, err := kit.ExternalIdentityService().Link(ctx, model.LinkExternalIdentityRequest{
    UserID:        userID,
    Provider:      pending.Provider,
    Subject:       pending.Subject,
    Email:         pending.Email,
    EmailVerified: pending.EmailVerified,
})
```

Use the same call from an account settings page to add a sign-in method. `Link`
applies no email rules because the caller vouches for `UserID`. It returns
`ErrIdentityAlreadyLinked` when another user has the identity; linking one the
user already has refreshes its email. `Unlink(ctx, userID, provider, subject)`
removes one of the user's links (`ErrNotFound` if it is not theirs). authkit does
not stop a user from removing their last way to sign in, because that depends on
which methods your application offers. `Get` and `ListByUser` are management reads.

Deleting a user row removes its links. A disabled user's links remain.

### Which emails to trust

Set `EmailVerified` only when the provider asserts that it verified the address
and you trust that assertion for this provider:

- **Google**: the ID token's `email_verified` claim.
- **GitHub**: GitHub is OAuth 2.0, not OIDC. Use the numeric `id` from `GET /user`
  as the subject (as a decimal string), and take the email from `GET /user/emails`,
  using the primary entry only when its `verified` is true. The profile's `email`
  field can be empty or a public address.
- **Other OIDC issuers**: trust `email_verified` only from an issuer that controls
  the addresses it vouches for. Some multi-tenant issuers let a tenant administrator
  set any email on an account; treat those as unverified (`EmailVerified: false`).

When in doubt, pass `EmailVerified: false`. Sign-ins still work for linked
identities, and new links need the owner.

### Google with go-oidc

A sketch of the callback; state, nonce and PKCE handling follow the go-oidc and
oauth2 documentation.

```go
provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
// ...
verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

token, err := oauthConfig.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(pkceVerifier))
if err != nil {
    return err
}
rawIDToken, ok := token.Extra("id_token").(string)
if !ok {
    return errors.New("no id_token")
}
idToken, err := verifier.Verify(ctx, rawIDToken)
if err != nil || idToken.Nonce != expectedNonce {
    return errors.New("invalid id_token")
}
var claims struct {
    Email         string `json:"email"`
    EmailVerified bool   `json:"email_verified"`
    Name          string `json:"name"`
}
if err := idToken.Claims(&claims); err != nil {
    return err
}
res, err := kit.ExternalIdentityService().Resolve(ctx, model.ResolveExternalIdentityRequest{
    Provider: "google", Subject: idToken.Subject,
    Email: claims.Email, EmailVerified: claims.EmailVerified,
    DisplayName: claims.Name, CreateUser: true,
})
if err != nil {
    return err // handle ErrIdentityLinkRequired as above
}
login, err := kit.VerifiedLoginService().OpenSession(ctx, model.OpenSessionRequest{
    UserID: res.User.ID, SignInMethod: "google",
})
```

A user that `Resolve` creates has no workspace yet. Add a membership with
`MembershipService.Add`, then mint a workspace token from `login.RefreshToken`.

## Errors

New sentinels: `ErrIdentityLinkRequired` (map to 409, or send the person to the
linking flow), `ErrIdentityAlreadyLinked` (409) and `ErrEmailNotVerified` (400 or
403). Malformed input returns `ErrInvalidInput`, a value longer than its column
`ErrValueTooLong`, and database faults stay sanitized as `ErrInternal`, including a
missing migration.
