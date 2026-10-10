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
		keyContext, err := identity.APIKeyService().Validate(r.Context(), apiKey)
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
   `InvitationService.Accept`, which validates the invitation, consumes one use,
   resolves the invitee's **global identity** (reusing an existing one for the email,
   or creating one), and grants the invited membership — all in a single transaction.
   It returns `(userID, created, err)`; `created == false` means an existing identity
   was reused (the invitee keeps their single account/password — no second login).

Use `Accept` for redemption — it provides atomic, all-or-nothing
semantics, so a single-use invitation can't be over-redeemed. Composing
`Validate` + your own user creation + `IncrementUseCount` is non-atomic
and can over-redeem under concurrency; those remain available only as lower-level
building blocks.

Note: `Accept` checks the invitation's expiry, remaining uses, and that
the email matches the invitation — it does **not** check the tenant's
`allowed_domains`. If you require invited users to stay within the tenant's domain
list, call `TenantService.ValidateDomainAccess` before creating the invitation.

## Rate Limiting

The library does not rate-limit itself. Inject a `Config.RateLimiter` and it is
consulted before `Login`, `RefreshToken`, and `OTPService.Generate`; a rejection
surfaces as `authkit.ErrRateLimited` (HTTP 429). `ValidateJWT` is a local check and is
**not** rate-limited, so handle 429 in the login/refresh/OTP handlers, not the JWT
middleware.

```go
type bucketLimiter struct{ /* redis or in-memory token bucket */ }

// Return (false, nil) to reject; return an error ONLY for a backend fault — the
// library fails open on errors (and counts authkit_rate_limiter_error_total).
func (l *bucketLimiter) Allow(ctx context.Context, key string) (bool, error) {
	return l.bucket.Allow(key), nil
}

identity, _ := authkit.New(authkit.Config{ /* ... */, RateLimiter: &bucketLimiter{} })

// In a login handler:
resp, err := identity.AuthService().Login(r.Context(), req)
switch {
case errors.Is(err, authkit.ErrRateLimited):
	http.Error(w, "too many requests", http.StatusTooManyRequests) // 429
case errors.Is(err, authkit.ErrNoActiveMembership):
	http.Error(w, "forbidden", http.StatusForbidden)               // 403 — valid creds, not a member of that workspace
case errors.Is(err, authkit.ErrInvalidCredentials):
	http.Error(w, "invalid credentials", http.StatusUnauthorized)  // 401
case err != nil:
	http.Error(w, "internal error", http.StatusInternalServerError)
}
```

The `key` passed to `Allow` is `login:<tenant>:<ip|email:...>` (`Login`),
`login:<ip|email:...>` (`LoginByEmail`, no tenant), `refresh:<ip>`,
`otp:<email>:<purpose>` (OTP is keyed by email + purpose, not tenant), or
`second_factor:<userID>` (`TwoFactorService.CompleteSecondFactor`) — bucket on it directly.

## Health Checks

`New` does not contact the database unless `Config.VerifyConnectivity` is set (so a bad
DSN otherwise surfaces on the first query). Set it for fail-fast startup, and call
`AuthKit.Ping` from a readiness probe — it pings both the RW and RO handles:

```go
identity, err := authkit.New(authkit.Config{ /* ... */, VerifyConnectivity: true })
if err != nil { log.Fatal(err) } // unreachable DB fails construction

func readyz(w http.ResponseWriter, r *http.Request) {
	if err := identity.Ping(r.Context()); err != nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable) // 503
		return
	}
	w.WriteHeader(http.StatusOK)
}
```

## Cleanup Jobs

Run cleanup jobs periodically:

```go
_, _ = identity.APIKeyService().CleanupExpired(ctx)
_, _ = identity.OTPService().CleanupExpired(ctx)
_, _ = identity.InvitationService().CleanupExpired(ctx)
_, _ = identity.TokenService().CleanupExpired(ctx)
// The account status-change audit table has no expiry and grows unbounded — prune it
// per your retention policy (olderThan must be positive):
_, _ = identity.UserService().CleanupStatusChanges(ctx, 90*24*time.Hour)
```

Choose the schedule based on your data volume. Hourly for OTPs and daily for longer-lived artifacts (including the status-change audit trim) is a reasonable starting point.

## Secret Rotation

`SecretService` encrypts values before storage but does not implement key rotation.

A practical rotation plan:

1. Add a new encryption key in application configuration.
2. Read each secret with the old key.
3. Save it again with the new key.
4. Remove the old key after verification.

For multi-key rotation, applications can wrap `SecretService` and select keys by version metadata stored outside this library.
