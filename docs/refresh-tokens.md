# Refresh tokens

A refresh token is single use. Each refresh consumes the presented token and returns a
new one in the same family (one family per login). Presenting a token that was already
consumed is treated as theft: authkit revokes the family, bumps the user's
`token_version` so every access token issued to them stops validating, and returns
`ErrRefreshTokenReuse`. With installation sessions it also revokes that session.

Strict rotation has one cost: a client that loses the response to a refresh still holds
the old token, so its next refresh looks like theft and signs the person out everywhere.
A response is lost when a request times out after the server committed, when the client
crashes or is killed before it saves the new token, or when a command-line tool or hook
is cut off by its own time limit.

## The grace period

`JWTConfig.RefreshGracePeriod` lets such a client retry:

```go
kit, err := authkit.New(authkit.Config{
    JWTConfig: authkit.JWTConfig{
        // ...
        RefreshGracePeriod: 24 * time.Hour,
    },
    // ...
})
```

With a grace period, a consumed token can be exchanged again for up to that long after
it was consumed, as long as the token that replaced it has never been used. The retry
returns a new pair and revokes the unused replacement. Everything else is unchanged:

| The old token is presented again | Result |
|---|---|
| Within the period, its replacement never used | A new pair; the unused replacement is revoked |
| Its replacement has been used | Reuse: the family is revoked |
| After the period | Reuse: the family is revoked |
| After a logout (the replacement is revoked or deleted) | As without a grace period: reuse, a revoked session, or an unknown token |
| Into a workspace the user has left | `ErrNoActiveMembership`; nothing is consumed |

The old token keeps working only until its replacement is used, so a stolen token is
still caught. If the owner refreshes first, the old token is dead and the thief's try
is reuse. If the thief refreshes first, the owner's replacement is revoked, and the
owner's next refresh is reuse, which revokes the thief's tokens too. Either way the
second of the two to refresh trips detection, as with strict rotation, and the
`authkit_refresh_token_reuse_total` counter and the reuse log fire.

### Choosing the period

The period has to cover the time between a lost response and the client's next
refresh. A browser or mobile app retries within seconds, so a minute is plenty. A
command-line tool or a hook may not run again for hours, so give it a day or more.
A longer period does not hide theft, for the reason above; it only bounds how long an
old token stays exchangeable while its replacement sits unused. What it does change is
the worth of a leaked old token: within the period, while the replacement is unused, it
buys the same access as stealing the current token would, until the owner's next
refresh trips detection. Strict rotation catches that old token at once. Zero, the
default, keeps strict rotation.

### Concurrent refreshes

Refresh one token from one place at a time. With a grace period, two refreshes of the
same token at once both succeed, but the second revokes the token the first returned,
so if the first one's token is the one the client keeps, its next refresh is reuse.
Without a grace period the second refresh is reuse straight away. Clients that refresh
from several processes should share the token behind a lock.

## Setting it up

1. Apply migration `000006_refresh_token_replacement`. It adds a nullable column,
   `refresh_tokens.replaced_by`, and is safe while older code runs. See
   [migrations.md](migrations.md).
2. Deploy with `RefreshGracePeriod` set.

Code without a grace period never reads or writes the column, so 000006 is needed only
for this setting. Tokens consumed before the period was set have no recorded
replacement and are not retryable.

Each retry logs `refresh_token_retry` at info level and increments
`authkit_refresh_token_retry_total`. A steady rate means clients are losing responses;
look at their timeouts.
