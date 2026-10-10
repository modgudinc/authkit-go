# Passkeys

`PasskeyService` stores WebAuthn credentials, passkeys and security keys, so people
can sign in with them. authkit keeps what the WebAuthn specification calls the
credential record, and each user's WebAuthn user handle, and checks the parts that
need the database: a credential is registered once, a removed passkey stops working
at once, and a signature counter that goes backwards is refused.

authkit does not run the WebAuthn ceremonies, as it does not speak OAuth. Verify
them with a WebAuthn library such as
[`github.com/go-webauthn/webauthn`](https://github.com/go-webauthn/webauthn), keep
the results with `PasskeyService`, and open the session with
`VerifiedLoginService.OpenSession` ([verified-sign-in.md](verified-sign-in.md)). The
examples below use go-webauthn v0.18.

## Turning it on

Apply migration `000008_passkeys`. It only adds two tables, so it is safe while
older code runs; see [migrations.md](migrations.md). Nothing else is configured:
`kit.PasskeyService()` needs only the migration.

## What authkit keeps

- **A user handle per relying party.** WebAuthn gives each account an opaque user
  handle that the authenticator stores with the passkey and returns when someone
  signs in without typing a username. authkit makes it 64 random bytes, never the
  user id or email, the first time `User` is called for that user and RP ID, and
  keeps it for the life of the account.
- **One `model.Passkey` per credential**, keyed by RP ID and credential ID: the
  public key, the signature counter, the transports, the user-verified
  (uvInitialized), backup-eligible and backup-state flags, the authenticator's
  AAGUID, the attestation if you keep it, the person's label for it, and when it
  was registered and last used.

Everything is per RP ID (the `RPID` of your WebAuthn configuration, such as
`example.com`), because a passkey works only at the RP ID it was made for. Use the
same RP ID string in every call; it is lowercased.

## Wiring go-webauthn

go-webauthn asks for a `webauthn.User`. This adapter presents authkit's record of a
user:

```go
// passkeyUser presents authkit's record of a user to go-webauthn.
type passkeyUser struct{ *model.PasskeyUser }

func (u passkeyUser) WebAuthnID() []byte          { return u.UserHandle }
func (u passkeyUser) WebAuthnName() string        { return u.User.Email }
func (u passkeyUser) WebAuthnDisplayName() string { return u.User.DisplayName }

func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential {
    creds := make([]webauthn.Credential, 0, len(u.Passkeys))
    for _, p := range u.Passkeys {
        transports := make([]protocol.AuthenticatorTransport, 0, len(p.Transports))
        for _, t := range p.Transports {
            transports = append(transports, protocol.AuthenticatorTransport(t))
        }
        var flags protocol.AuthenticatorFlags
        if p.UserVerified {
            flags |= protocol.FlagUserVerified
        }
        if p.BackupEligible {
            flags |= protocol.FlagBackupEligible
        }
        if p.BackupState {
            flags |= protocol.FlagBackupState
        }
        creds = append(creds, webauthn.Credential{
            ID:                p.CredentialID,
            PublicKey:         p.PublicKey,
            AttestationType:   p.AttestationType,
            AttestationFormat: p.AttestationFormat,
            Transport:         transports,
            Flags:             webauthn.NewCredentialFlags(flags),
            Authenticator:     webauthn.Authenticator{AAGUID: p.AAGUID, SignCount: p.SignCount},
            Attestation: webauthn.CredentialAttestation{
                Object:         p.AttestationObject,
                ClientDataJSON: p.AttestationClientDataJSON,
            },
        })
    }
    return creds
}
```

Between the two steps of each ceremony, keep go-webauthn's `SessionData` on the
server, tied to the person's browser session, and never in a cookie or form field
the client can change.

### Add a passkey

For a person who is already signed in as `userID`:

```go
// Begin: User creates the person's user handle at rpID the first time.
pu, err := kit.PasskeyService().User(ctx, userID, rpID)
if err != nil {
    return err
}
user := passkeyUser{pu}
options, session, err := wa.BeginRegistration(user,
    webauthn.WithExclusions(webauthn.Credentials(user.WebAuthnCredentials()).CredentialDescriptors()),
    webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
)
// Keep session on the server; send options to the browser.

// Finish, with the browser's response in r:
pu, err = kit.PasskeyService().User(ctx, userID, rpID)
if err != nil {
    return err
}
cred, err := wa.FinishRegistration(passkeyUser{pu}, *session, r)
if err != nil {
    return err
}
transports := make([]string, 0, len(cred.Transport))
for _, t := range cred.Transport {
    transports = append(transports, string(t))
}
passkey, err := kit.PasskeyService().Register(ctx, model.RegisterPasskeyRequest{
    UserID:                    userID,
    RPID:                      rpID,
    Name:                      name, // the person's label, such as "MacBook"
    CredentialID:              cred.ID,
    PublicKey:                 cred.PublicKey,
    SignCount:                 cred.Authenticator.SignCount,
    Transports:                transports,
    UserVerified:              cred.Flags.UserVerified,
    BackupEligible:            cred.Flags.BackupEligible,
    BackupState:               cred.Flags.BackupState,
    AAGUID:                    cred.Authenticator.AAGUID,
    AttestationType:           cred.AttestationType,
    AttestationFormat:         cred.AttestationFormat,
    AttestationObject:         cred.Attestation.Object,
    AttestationClientDataJSON: cred.Attestation.ClientDataJSON,
})
```

`WithExclusions` keeps an authenticator from registering a second passkey for the
same account. `Register` returns `ErrPasskeyAlreadyRegistered` when the credential
ID is already registered at the RP ID, to anyone, as WebAuthn requires, and
`ErrNotFound` when the user has no handle there, which means `User` was not called
before the ceremony. The attestation fields are optional: keep them to check the
authenticator against FIDO metadata later, or leave them empty.

As with `ExternalIdentityService.Link`, `UserID` must come from your own signed-in
session. Ask for a recent sign-in before adding a passkey, since a passkey is a new
way into the account.

### Sign in with a passkey

A discoverable sign-in needs no username: the browser offers the person's passkeys
for your site, and the one they choose returns its user handle.

```go
// Begin:
options, session, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
// Keep session on the server; send options to the browser.

// Finish, with the browser's response in r:
user, cred, err := wa.FinishPasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
    pu, err := kit.PasskeyService().UserByHandle(ctx, rpID, userHandle)
    if err != nil {
        return nil, err
    }
    return passkeyUser{pu}, nil
}, *session, r)
if err != nil {
    return err
}
userID := user.(passkeyUser).User.ID
if err := kit.PasskeyService().RecordUse(ctx, model.PasskeyUseRequest{
    UserID:       userID,
    RPID:         rpID,
    CredentialID: cred.ID,
    SignCount:    cred.Authenticator.SignCount,
    UserVerified: cred.Flags.UserVerified,
    BackupState:  cred.Flags.BackupState,
}); err != nil {
    return err // authkit.ErrPasskeyCloned: refuse the sign-in
}
login, err := kit.VerifiedLoginService().OpenSession(ctx, model.OpenSessionRequest{
    UserID:       userID,
    SignInMethod: "passkey",
    SessionInfo:  &model.SessionInfo{IPAddress: ip, UserAgent: ua},
})
```

`RecordUse` writes back what the sign-in changed, and must come before
`OpenSession`:

- The signature counter must go up from the passkey's last use. If it did not, the
  passkey may have been copied to another authenticator: `RecordUse` returns
  `ErrPasskeyCloned`, changes nothing, logs a warning and counts
  `authkit_webauthn_clone_warning_total`. Refuse the sign-in and tell the person.
  Most synced passkeys always report 0, and a passkey that reported 0 and still
  does passes. The check and the write hold the passkey's row lock, so two sign-ins
  cannot both pass with the same count.
- The backup state is stored as the authenticator reports it, and the
  user-verified flag is only ever set, as WebAuthn specifies.
- `ErrNotFound` means the passkey is gone, for example removed while the person was
  signing in.

Require user verification (a PIN or biometric) when the passkey is the only factor,
as above: without it a passkey proves only that someone holds the device.
`OpenSession` then applies the account gates (`ErrAccountDisabled`,
`ErrAccountLocked`) and workspace selection, and, with `Config.RecordSignIns`,
records the sign-in with method `passkey`. Throttle these endpoints as you would a
password login; `OpenSession` does not consult `Config.RateLimiter`.

For a sign-in that names the user first (an email, then a passkey), load the user
with `User` and use `wa.BeginLogin` and `wa.FinishLogin` with the same adapter.
Telling a stranger which emails have passkeys is then up to your flow.

## Managing passkeys

```go
passkeys, err := kit.PasskeyService().List(ctx, userID, rpID) // oldest first
err = kit.PasskeyService().Rename(ctx, userID, rpID, credentialID, "Work laptop")
err = kit.PasskeyService().Remove(ctx, userID, rpID, credentialID)
```

Authorize the caller before passing a `userID`: a person manages their own
passkeys, and an administrator whoever your policy allows. A passkey that belongs
to someone else is `ErrNotFound`. Credential IDs are bytes; encode them with
base64url for a URL. `List` reads the replica and creates nothing, so it suits a
settings page; the ceremony calls (`User`, `UserByHandle`) read the primary, so a
removed passkey stops working at once.

authkit does not stop a person from removing their last way to sign in, because
that depends on which methods your application offers. Check it before calling
`Remove` if it matters. The user handle stays after the last passkey is removed,
so a passkey added later carries the same one.

Deleting the user row deletes their handles and passkeys. `UserService.Delete`
only disables the account, and a disabled account's passkeys cannot open a session.

## Errors

| Error | When | HTTP |
|---|---|---|
| `ErrPasskeyAlreadyRegistered` | `Register`: the credential ID is already registered at the RP ID | 409 |
| `ErrPasskeyCloned` | `RecordUse`: the signature counter did not go up | 401 |
| `ErrNotFound` | An unknown user, user handle or passkey, or `Register` before `User` | 404, or 401 while signing in |
| `ErrInvalidInput` | A malformed RP ID, an empty or over-long credential ID, a bad AAGUID, transport or attestation name, or a backed-up passkey that is not backup eligible | 400 |
| `ErrValueTooLong` | A label over 255 characters | 400 |

Database faults are `ErrInternal`, including a missing migration.
