# Installation-bound sessions

Installation sessions let an application attach a login to an enrolled app
installation and revoke that login without invalidating other installations.
Session support is disabled by default.

## Configure

Apply `000002_installation_sessions.up.sql` and then
`000003_session_sign_in.up.sql` after the identity migration before enabling the
feature. `authkit.Migrations` returns them all, and for a custom `IdentitySchema`
it names your schema in place of `authkit` ([migrations.md](migrations.md)).

```go
config.SessionConfig = authkit.SessionConfig{
    Mode:             authkit.SessionRequired,
    Namespace:        "desktop",
    AbsoluteLifetime: 30 * 24 * time.Hour,
}
kit, err := authkit.New(config)
if err != nil {
    return err
}
```

| Mode | Contract |
| --- | --- |
| `SessionDisabled` (zero value) | Legacy issuance/validation and old-schema operation; no session queries. Bound credentials return `ErrSessionDisabled`. |
| `SessionOptional` | Both legacy and installation-bound login. A token claiming a session must pass session validation; it cannot fall back to legacy. |
| `SessionRequired` | Only bound access/refresh/workspace-mint flows. Legacy login and low-level unbound token issuance return `ErrSessionRequired`. |

`Namespace` is a non-empty application/client identifier, at most 255 characters.
It is independent of tenant/workspace membership. Use consistent namespace,
issuer, audience and mode across an application's issuers and validators.

`AbsoluteLifetime` defaults to 30 days when enabled and must be at least one
second. `JWTConfig.RefreshExpiry` controls the sliding idle lifetime. Successful
refresh extends that deadline up to the fixed absolute limit. Access tokens are
capped at the current session deadline; JWT dates have second precision.
JWT validation and workspace switching do not extend the idle deadline.

## Enroll, then log in

Enrollment is application-owned. Authenticate the enrollment flow and verify the
installation's ownership/proof before passing its ID to authkit. Do not copy an
arbitrary body-supplied ID into the binding. Authentication-only enrollment must
not grant access to protected device or relay APIs.

```go
login, err := kit.InstallationAuthService().LoginWithInstallation(ctx,
    model.InstallationLoginRequest{
        LoginRequest: model.LoginRequest{
            Email: email, Password: password, TenantID: tenantID,
            SessionInfo: &model.SessionInfo{DeviceName: "MacBook"},
        },
        Installation: model.InstallationBinding{
            InstallationID: verifiedInstallationID,
        },
    })
if err != nil {
    return err
}
// Store login.RefreshToken securely on this installation.
// login.Session.ID identifies this login, not the physical device.
```

`LoginByEmailWithInstallation` accepts
`model.InstallationLoginByEmailRequest` when the workspace is not known.
It returns a bound session even if workspace selection is still required.
Both methods return `InstallationLoginResponse`, embedding the unchanged
`LoginResponse` plus `Session`.

A new login creates a new UUIDv7 session ID. It is also the refresh family's ID
and the access token's signed `sid` claim. The installation ID is stored in the
session record; device names, IP addresses and user agents remain metadata.
Multiple logins may belong to the same installation.

An installation ID is not a credential. These remain bearer tokens: binding
provides association and revocation, not proof of possession on every request.
Device-key proof, sender-constrained tokens, pairing, permissions and E2EE are
separate application concerns.

## Sessions without an installation

`VerifiedLoginService.OpenSession` opens a session for a user the application
verified itself (an OAuth or OIDC provider, an email link, a device code). Without
an `Installation` it creates a session record whose `InstallationID` is empty, in
Optional and Required mode alike: a browser session that is listed, revoked and
expired like any other. Every session records its `SignInMethod` (`"password"` for
the installation logins above). See [verified sign-in](verified-sign-in.md).

## Validate, refresh and switch workspace

```go
identity, err := kit.InstallationAuthService().ValidateInstallationJWT(ctx, token)
if err != nil {
    return err
}
userID := identity.Claims.UserID
installationID := identity.Session.InstallationID
// Authorize the requested operation using this verified binding.
```

`AuthService.ValidateJWT` also validates bound sessions, while returning the
existing `JWTClaims` result. `ValidateInstallationJWT` requires a binding even in
Optional mode and returns the session metadata as well; it refuses a session with
no installation with `ErrSessionRequired`.

Validation checks signature, JWT expiry, account state/version, active workspace
membership/version, session owner, namespace, revocation, and idle/absolute expiry.
Security reads use the primary database. Missing session records fail closed.
`SessionService.Get/List` are management reads, not authentication checks.
`JWTService.ValidateAccessToken` only validates cryptographic claims and mode;
it does not check database revocation. Use the AuthService validation boundary.

Use the existing `AuthService.RefreshToken` and `MintWorkspaceToken` methods.
They preserve the stored session/installation and cannot rebind it. Refresh
rotates credentials and JWT `jti`, while `sid` remains stable across workspaces.
A rejected workspace does not consume a live refresh token.

Treat refresh tokens as opaque. Bound tokens have a version marker covered by
their stored HMAC; this prevents legacy fallback when session data is missing.
Clients must not strip the marker, assume a fixed length, or decode the token.
Legacy token output remains unchanged.

Serialize refresh per installation and persist the replacement pair atomically.
Reusing a consumed token on an active session triggers the existing broad
identity-token-version response. Bound sessions additionally remember the
identity version at login, so a credential-version change invalidates their
refresh capability too. A lost successful refresh response therefore needs
re-authentication; blindly replaying the old token is unsafe.

## Manage and revoke

```go
sessions, err := kit.SessionService().List(ctx, authorizedUserID, 50, 0)
// List/Get include expired and revoked records. List limit is 1..200.

err = kit.SessionService().Revoke(ctx, authorizedUserID, sessionID)
err = kit.SessionService().RevokeInstallation(ctx, authorizedUserID, installationID)
```

Every operation is scoped to the configured namespace and supplied user.
The embedding application must authorize the actor before supplying that user.
A session belonging to another owner/namespace is not found. Revoke is idempotent
for an existing revoked record. Revoking an installation with no matching
sessions succeeds without affecting other installations.

Session revocation marks the record and revokes its live refresh descendants
transactionally, so existing access tokens also fail validation. It does not
bump the user's identity version. `AuthService.Logout` closes a bound session,
including when supplied an older consumed token from that session.
Retrying an intentionally revoked session reports revocation instead of
triggering another identity-wide reuse response.

With support enabled, explicit account-wide credential actions also revoke bound
session records across namespaces. Account disable, password changes, logout-all
and membership checks retain their existing security gates. Session management
does not prevent a fresh login: the application must revoke the installation's
enrollment when removing a device.

Bound mutations lock user, then session, then refresh rows. Optional-mode legacy
rotation takes the same user-first ordering to coordinate with account-wide
revocation. A token minted by a racing refresh cannot validate after revocation
has committed.

Authkit does not close connections. Applications must revalidate protected
traffic, close sockets at token expiry, and distribute/recheck revocation state.
There is no claim that an already-authorized in-flight action can be undone.

Run both `TokenService.CleanupExpired` and `SessionService.CleanupExpired`
periodically. Session cleanup is namespace-scoped and removes records only after
their idle expiry; ciphertext, device keys and message retention are outside
this library. `LastUsedAt` reflects login/refresh, not continuous socket activity.

## Upgrade compatibility

Existing named service interfaces and request/response structs keep their
signatures and shapes. New APIs use separate interfaces and request wrappers.
`Config` and `JWTClaims` gain fields; consumers using positional literals for
those two exported structs must switch to keyed literals. Public claims remain
safe to embed in consumer-defined JSON claim types.

Default mode works without migrations 000002 and 000003. The forward migrations
leave the released identity migration and existing unbound families intact. Never
infer bindings from device names, IP addresses or user agents.

Applications already running 000002 must apply 000003 before deploying a release
that includes it: session queries read the new `sign_in_method` column. The
migration is safe while older code runs (the column defaults to `"password"`).
Rolling it back deletes the sessions that have no installation, and their refresh
tokens, before restoring the installation constraint.

Deploy session-aware code to every validator before issuing bound tokens. Old
code ignores `sid` and cannot enforce session revocation. Use Optional only for
deliberate migration; switching to Required requires enrollment-bound login for
legacy sessions. Do not upgrade a legacy refresh token just by attaching a
client-provided installation ID.

Before rolling back to older validators or dropping the new table, invalidate
bound credentials or isolate their issuer. New Disabled validators explicitly
reject bound tokens; old validators cannot provide that guarantee.

New sentinels: `ErrSessionDisabled`, `ErrSessionRequired` and
`ErrSessionRevoked`. Malformed claims return `ErrInvalidToken`, invalid bindings
return `ErrInvalidInput`, and database faults remain sanitized as `ErrInternal`.
