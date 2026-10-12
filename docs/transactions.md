# Running authkit in your own transaction

Each authkit call commits on its own. That is a problem when your application has to
record what changed in the same transaction as the change, as a transactional outbox
does: if authkit commits and your process dies before your own write, the change
happened and nothing downstream ever hears of it.

`AuthKit.InTx` and `authkit.WithTx` run authkit's calls in your transaction instead,
so they commit or roll back together with your own writes.

```go
err := kit.InTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
	userID, _, err := kit.InvitationService().Accept(ctx, model.AcceptInvitationRequest{
		Code: code, Email: email, DisplayName: name,
	})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO app.outbox (kind, user_id, invitation) VALUES ('invitation_accepted', $1, $2)`,
		userID, code)
	return err
})
```

`InTx` begins a transaction on the read-write identity database, passes your function a
context that makes authkit use it, and commits if the function returns nil. Otherwise it
rolls back, and neither the acceptance nor the outbox row happened.

If you begin the transaction yourself, `authkit.WithTx(ctx, tx)` returns the context
to call authkit with; committing stays with you. The transaction has to be on the
database that holds the identity schema (`Config.DBConnection`).

Several calls can share one transaction, so removing someone from a workspace and
signing them out everywhere happen together or not at all:

```go
err := kit.InTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
	if err := kit.MembershipService().RemoveGuarded(ctx, userID, tenantID, "admin"); err != nil {
		return err
	}
	if err := kit.AuthService().LogoutAll(ctx, userID); err != nil {
		return err
	}
	return recordRemoval(ctx, tx, userID)
})
```

## What runs in it

Every query authkit runs for that context goes to your transaction, reads included, so
a read sees what was written before it in the same transaction. Where authkit would
begin a transaction of its own (accepting an invitation, a guarded membership change, a
status change and its audit row, linking an identity), it sets a savepoint in yours.
When such a step fails, it rolls back to its savepoint and returns its error, and your
transaction carries on. A refused `RemoveGuarded` or a mismatched invitation email is
that kind of failure.

A single statement that fails, such as `UserService.Create` for an email that is taken,
leaves the transaction aborted, as Postgres does for any failed statement. Treat an
error from authkit inside your transaction as the end of it and roll back, as `InTx`
does when your function returns the error.

A transaction-scoped advisory lock authkit takes, such as the guard's lock on a tenant,
is held until your transaction ends rather than until the step does.

## What commits on its own

Signing in and checking a credential ignore your transaction and commit on their own,
because what they record has to stay recorded whatever you do with it: a failed attempt
and the lockout it leads to, a refresh token family revoked for reuse, a one-time or
two-factor code used up, a passkey's signature counter. Those calls are the
`AuthService`, `InstallationAuthService` and `VerifiedLoginService` sign-ins,
`AuthService.MintWorkspaceToken`, `RefreshToken`, `ValidateJWT` and `ChangePassword`,
every `TokenService` call that issues or checks a token, `OTPService.Generate` and
`Validate`, `TwoFactorService.ConfirmTOTP`, `Verify` and `CompleteSecondFactor`,
`APIKeyService.Validate` and `PasskeyService.RecordUse`. The `last_used_at` updates
authkit makes in the background are outside it too.

`AuthService.Logout` and `LogoutAll`, `SessionService.Revoke` and `RevokeInstallation`,
and the user, membership, invitation, tenant, identity and secret changes all run in
it.
