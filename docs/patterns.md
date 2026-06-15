# Common Patterns

## Single Database Connection

For small deployments or local development, use the same database handle for read and write connections. The library uses `database/sql`; register the pgx driver with a blank import (`_ "github.com/jackc/pgx/v5/stdlib"`) and open with the `pgx` driver name:

```go
db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
if err != nil {
	return err
}

identity, err := authkit.New(authkit.Config{
	DBConnection: authkit.DatabaseConnection{
		IdentityRWDB: db,
		IdentityRODB: db,
	},
	// other config...
})
```

## Read Replica Deployment

Use a writer for `IdentityRWDB` and a replica for `IdentityRODB`.

Security-sensitive validation paths use `IdentityRWDB` internally to avoid accepting revoked API keys or refresh tokens during replica lag.

## HTTP Bearer JWT Middleware

```go
func RequireJWT(identity *authkit.AuthKit, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		token := strings.TrimPrefix(header, "Bearer ")
		if token == header || token == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		claims, err := identity.AuthService().ValidateJWT(r.Context(), token)
		if err != nil {
			switch {
			case errors.Is(err, authkit.ErrAccountDisabled), errors.Is(err, authkit.ErrAccountLocked):
				http.Error(w, "forbidden", http.StatusForbidden) // 403
			case errors.Is(err, authkit.ErrInvalidToken), errors.Is(err, authkit.ErrTokenRevoked):
				http.Error(w, "unauthorized", http.StatusUnauthorized) // 401
			default:
				// ErrInternal or unexpected: log server-side, return 500 — not 401
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
			return
		}

		ctx := context.WithValue(r.Context(), claimsContextKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
```

## API Key Middleware

```go
func RequireAPIKey(identity *authkit.AuthKit, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		keyContext, err := identity.APIKeyService().ValidateAPIKey(r.Context(), apiKey)
		if err != nil {
			http.Error(w, "invalid API key", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), apiKeyContextKey{}, keyContext)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
```

## Signup With Invitation And OTP

One common flow:

1. Admin creates an invitation.
2. User starts signup with the invited email.
3. Application validates the OTP it sent to the invited email.
4. User submits OTP and password.
5. Application validates the OTP, hashes the password, and calls
   `InvitationService.AcceptInvitation`, which validates the invitation, consumes
   one use, and creates the user in a single transaction.

Use `AcceptInvitation` for redemption — it provides atomic, all-or-nothing
semantics, so a single-use invitation can't be over-redeemed. Composing
`ValidateInvitation` + your own user creation + `IncrementUseCount` is non-atomic
and can over-redeem under concurrency; those remain available only as lower-level
building blocks.

Note: `AcceptInvitation` checks the invitation's expiry, remaining uses, and that
the email matches the invitation — it does **not** check the tenant's
`allowed_domains`. If you require invited users to stay within the tenant's domain
list, call `TenantService.ValidateDomainAccess` before creating the invitation.

## Cleanup Jobs

Run cleanup jobs periodically:

```go
_, _ = identity.APIKeyService().CleanupExpiredKeys(ctx)
_, _ = identity.OTPService().CleanupExpired(ctx)
_, _ = identity.InvitationService().CleanupExpiredInvitations(ctx)
_, _ = identity.TokenService().CleanupExpiredTokens(ctx)
```

Choose the schedule based on your data volume. Hourly for OTPs and daily for longer-lived artifacts is a reasonable starting point.

## Secret Rotation

`SecretService` encrypts values before storage but does not implement key rotation.

A practical rotation plan:

1. Add a new encryption key in application configuration.
2. Read each secret with the old key.
3. Save it again with the new key.
4. Remove the old key after verification.

For multi-key rotation, applications can wrap `SecretService` and select keys by version metadata stored outside this library.
