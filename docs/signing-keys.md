# Signing keys

By default authkit signs access tokens with HS256 and `JWTConfig.AccessSecret`. Every
service that checks a token then needs that secret, and anything holding it can also
mint tokens. With an asymmetric signing key, only the application running authkit holds
the private key. Everything else checks tokens with the public half, published as a JSON
Web Key Set. Each token names its key in the `kid` header, so keys can be rotated
without logging anyone out.

## Choosing a key

| Key | Algorithm | Notes |
|-----|-----------|-------|
| Ed25519 | `EdDSA` | Small and fast. Some API gateways and older JOSE libraries do not support it. |
| ECDSA on P-256 | `ES256` | Widely supported, small tokens. |
| RSA, 2048 bits or more | `RS256` | The widest support. Larger keys and signatures. |

The key's type picks the algorithm. Other curves, RSA keys under 2048 bits, and other
algorithms (PS256, ES384, HS384) are refused, so a token can never pick a weaker
variant.

## Generate a key

```bash
openssl genpkey -algorithm ed25519 -out access-key.pem
# or: openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out access-key.pem
# or: openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out access-key.pem

# The public half, for VerificationKeys elsewhere (not a secret):
openssl pkey -in access-key.pem -pubout -out access-key.pub.pem
```

Store the private key like any other root secret (see [SECURITY.md](../SECURITY.md)).

## Configure

```go
key, err := authkit.ParsePrivateKeyPEM([]byte(os.Getenv("JWT_SIGNING_KEY")))
if err != nil {
    return err
}
kit, err := authkit.New(authkit.Config{
    // ...
    JWTConfig: authkit.JWTConfig{
        SigningKey:             &authkit.SigningKey{ID: "2026-10", Key: key},
        RefreshTokenHMACSecret: os.Getenv("REFRESH_TOKEN_HMAC_SECRET"),
    },
})
```

- `ID` is optional. Left empty, it is the key's RFC 7638 thumbprint, so the same key
  always gets the same id. Set it when you want ids that say which key is which.
- `Key` is any `crypto.Signer`, so a key held in a KMS or an HSM works as long as its
  `Public()` is one of the types above. authkit calls `Sign` once for each access token
  it issues (login, refresh, workspace switch).
- `AccessSecret` becomes optional. If it is still set, it no longer signs anything. It
  only validates HS256 tokens issued before the switch.
- `ParsePrivateKeyPEM` reads PKCS #8, SEC 1 and PKCS #1 PEM. `ParsePublicKeyPEM` reads
  PKIX and PKCS #1. Encrypted PEM is refused, so decrypt the key first.

## Publish the key set

```go
mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Cache-Control", "public, max-age=300")
    _ = json.NewEncoder(w).Encode(kit.JSONWebKeySet())
})
```

`JSONWebKeySet` lists the signing key first, then `VerificationKeys`. Each key has
`kid`, `alg` and `use: "sig"`. The HS256 secret is never in it.

Another service, an API gateway or a JOSE library can check tokens against this set.
It should pick the key by `kid`, accept only that key's `alg`, and check `exp`, `iss`
and `aud`. What it cannot see is revocation: a bumped token version, a disabled or
locked account, a suspended membership, a revoked session. Only
`AuthService.ValidateJWT` checks those, against the database. A service that relies
on the key set alone accepts a revoked token until it expires, so keep `AccessExpiry`
short.

## How tokens are checked

`JWTService.ValidateAccessToken`, and so `AuthService.ValidateJWT`, picks the key from
the token's header:

- A token with a `kid` is checked against the configured key with that id, in that
  key's algorithm only.
- A token without a `kid` is checked as HS256 against `AccessSecret`, and only when
  `AccessSecret` is set. authkit never puts a `kid` on HS256 tokens.
- Everything else is `ErrInvalidToken`: an unknown `kid`, a `kid` that is not a string,
  a `kid` with another algorithm (including HS256 keyed with a public key), and `none`.
- Keys a token carries itself (`jwk`, `jku`, `x5c`, `x5u`) are never used.

## Moving off HS256

Every running instance has to accept a token before any instance issues it. With a
rolling deploy that takes three steps.

1. **Publish.** Keep `AccessSecret` and add the new key's public half to
   `VerificationKeys`. Tokens are still HS256, but every instance now accepts the new
   key, and the key set lists it.
2. **Switch.** Set `SigningKey` to the new key and keep `AccessSecret`. New tokens are
   signed with the key. HS256 tokens issued earlier still validate. Refresh tokens are
   not JWTs and are unaffected: the next refresh returns a signed access token.
3. **Retire the secret.** Once one `AccessExpiry` has passed since step 2 finished
   rolling out, remove `AccessSecret`. HS256 tokens are refused from then on.

A single instance that restarts in one go can skip step 1.

## Rotating a key

Rotating from key A to key B takes the same three steps:

1. `SigningKey` A, `VerificationKeys` [B]. If other services cache the key set, wait
   for their cache (the `max-age` above) to expire before step 2.
2. `SigningKey` B, `VerificationKeys` [A].
3. After one `AccessExpiry`, and the key set cache, drop A.

If a private key leaks, skip the waiting. Set a new `SigningKey` and remove the leaked
key everywhere at once. Tokens signed with it stop validating straight away, and
clients get new ones with their refresh tokens.
