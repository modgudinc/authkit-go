// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/model"
)

var (
	testRSAKeyOnce sync.Once
	testRSAKey     *rsa.PrivateKey
)

// sharedRSAKey generates one 2048-bit key for the whole package's tests.
func sharedRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testRSAKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testRSAKey = key
	})
	return testRSAKey
}

func newEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustAccessKeys(t *testing.T, signing *model.SigningKey, verification ...model.VerificationKey) *AccessKeys {
	t.Helper()
	keys, err := NewAccessKeys(signing, verification)
	if err != nil {
		t.Fatalf("new access keys: %v", err)
	}
	return keys
}

func keyedJWTService(secret string, keys *AccessKeys) *JWTService {
	return NewJWTService(secret, time.Minute, time.Hour, nil, WithAccessKeys(keys))
}

func mintToken(t *testing.T, s *JWTService) string {
	t.Helper()
	token, err := s.GenerateAccessToken(&model.User{ID: uuid.Must(uuid.NewV7()).String(), Email: "u@example.com"}, jwtTestMembership("tenant-a", "Member"))
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}
	return token
}

func tokenHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return header
}

func expectInvalidToken(t *testing.T, s *JWTService, token, what string) {
	t.Helper()
	if _, err := s.ValidateAccessToken(token); !errors.Is(err, model.ErrInvalidToken) {
		t.Fatalf("%s: expected ErrInvalidToken, got %v", what, err)
	}
}

// signedWith signs claims the way an attacker could: any algorithm, any header.
func signedWith(t *testing.T, method jwt.SigningMethod, key any, kid any) string {
	t.Helper()
	claims := model.JWTClaims{
		UserID:   uuid.Must(uuid.NewV7()).String(),
		TenantID: "tenant-a",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		},
	}
	token := jwt.NewWithClaims(method, claims)
	if kid != nil {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign forged token: %v", err)
	}
	return signed
}

func b64Decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestJWKThumbprintKnownAnswers checks default key ids against RFC 7638 section
// 3.1 (RSA) and RFC 8037 appendix A.3 (Ed25519). The P-256 value was computed
// independently from the RFC 7517 appendix A.1 key.
func TestJWKThumbprintKnownAnswers(t *testing.T) {
	const rsaN = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	const edX = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	const ecX, ecY = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"

	rsaPub := &rsa.PublicKey{N: new(big.Int).SetBytes(b64Decode(t, rsaN)), E: 65537}
	point := append([]byte{4}, append(b64Decode(t, ecX), b64Decode(t, ecY)...)...)
	ecPub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		t.Fatalf("parse P-256 key: %v", err)
	}

	for _, tc := range []struct {
		name string
		pub  crypto.PublicKey
		want model.JSONWebKey
	}{
		{"RSA", rsaPub, model.JSONWebKey{KeyType: "RSA", KeyID: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", Use: "sig", Algorithm: "RS256", N: rsaN, E: "AQAB"}},
		{"Ed25519", ed25519.PublicKey(b64Decode(t, edX)), model.JSONWebKey{KeyType: "OKP", KeyID: "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", Use: "sig", Algorithm: "EdDSA", Curve: "Ed25519", X: edX}},
		{"P-256", ecPub, model.JSONWebKey{KeyType: "EC", KeyID: "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s", Use: "sig", Algorithm: "ES256", Curve: "P-256", X: ecX, Y: ecY}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys := mustAccessKeys(t, nil, model.VerificationKey{Key: tc.pub})
			set := keys.JSONWebKeySet()
			if len(set.Keys) != 1 || set.Keys[0] != tc.want {
				t.Fatalf("key set = %+v, want %+v", set.Keys, tc.want)
			}
		})
	}
}

// TestAccessKeysSignAndValidate signs with each supported key type, directly and
// through an opaque crypto.Signer (as a KMS client would be), and checks the token
// with authkit and, independently, with golang-jwt and the public key alone.
func TestAccessKeysSignAndValidate(t *testing.T) {
	type opaqueSigner struct{ crypto.Signer }
	for _, tc := range []struct {
		name string
		key  crypto.Signer
		alg  string
	}{
		{"Ed25519", newEd25519Key(t), "EdDSA"},
		{"P-256", newP256Key(t), "ES256"},
		{"RSA", sharedRSAKey(t), "RS256"},
		{"Ed25519 signer", opaqueSigner{newEd25519Key(t)}, "EdDSA"},
		{"P-256 signer", opaqueSigner{newP256Key(t)}, "ES256"},
		{"RSA signer", opaqueSigner{sharedRSAKey(t)}, "RS256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys := mustAccessKeys(t, &model.SigningKey{Key: tc.key})
			s := keyedJWTService("", keys)
			token := mintToken(t, s)

			header := tokenHeader(t, token)
			kid := keys.JSONWebKeySet().Keys[0].KeyID
			if header["alg"] != tc.alg || header["kid"] != kid || kid == "" {
				t.Fatalf("header = %v, want alg %s and kid %s", header, tc.alg, kid)
			}
			claims, err := s.ValidateAccessToken(token)
			if err != nil || claims.TenantID != "tenant-a" {
				t.Fatalf("validate: claims %+v, err %v", claims, err)
			}

			parsed, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return tc.key.Public(), nil },
				jwt.WithValidMethods([]string{tc.alg}))
			if err != nil || !parsed.Valid {
				t.Fatalf("golang-jwt rejected the token: %v", err)
			}
		})
	}
}

func TestAccessKeysExplicitKeyID(t *testing.T) {
	keys := mustAccessKeys(t, &model.SigningKey{ID: "2026-10-primary", Key: newEd25519Key(t)})
	s := keyedJWTService("", keys)
	token := mintToken(t, s)
	if kid := tokenHeader(t, token)["kid"]; kid != "2026-10-primary" {
		t.Fatalf("kid = %v", kid)
	}
	if kid := keys.JSONWebKeySet().Keys[0].KeyID; kid != "2026-10-primary" {
		t.Fatalf("key set kid = %v", kid)
	}
	if _, err := s.ValidateAccessToken(token); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// TestJWTServiceMovesOffHS256 walks the documented switch from an HS256 secret to
// a signing key, one deploy at a time, without failing a token issued at any step.
func TestJWTServiceMovesOffHS256(t *testing.T) {
	const secret = "access-secret"
	next := newEd25519Key(t)

	before := NewJWTService(secret, time.Minute, time.Hour, nil)
	// Deploy 1: still signs HS256, already accepts the next key.
	publish := keyedJWTService(secret, mustAccessKeys(t, nil, model.VerificationKey{Key: next.Public()}))
	// Deploy 2: signs with the key, still accepts HS256 tokens from before.
	switched := keyedJWTService(secret, mustAccessKeys(t, &model.SigningKey{Key: next}))
	// Deploy 3, once HS256 tokens have expired: the secret is gone.
	after := keyedJWTService("", mustAccessKeys(t, &model.SigningKey{Key: next}))

	oldToken := mintToken(t, before)
	if _, ok := tokenHeader(t, oldToken)["kid"]; ok {
		t.Fatal("HS256 tokens must not carry a key id")
	}
	publishToken := mintToken(t, publish)
	if tokenHeader(t, publishToken)["alg"] != "HS256" {
		t.Fatal("verification keys alone must not change how tokens are signed")
	}
	newToken := mintToken(t, switched)

	for _, s := range []*JWTService{publish, switched} {
		for _, token := range []string{oldToken, publishToken, newToken} {
			if _, err := s.ValidateAccessToken(token); err != nil {
				t.Fatalf("token rejected during the switch: %v", err)
			}
		}
	}
	if _, err := after.ValidateAccessToken(newToken); err != nil {
		t.Fatalf("after: %v", err)
	}
	expectInvalidToken(t, after, oldToken, "HS256 token after the secret is removed")
	expectInvalidToken(t, before, newToken, "signed token on a kit that only knows the secret")
}

// TestJWTServiceRotatesKeys rotates from key A to key B with the same three steps.
func TestJWTServiceRotatesKeys(t *testing.T) {
	a, b := newP256Key(t), newEd25519Key(t)
	signA := keyedJWTService("", mustAccessKeys(t, &model.SigningKey{Key: a}))
	publishB := keyedJWTService("", mustAccessKeys(t, &model.SigningKey{Key: a}, model.VerificationKey{Key: b.Public()}))
	signB := keyedJWTService("", mustAccessKeys(t, &model.SigningKey{Key: b}, model.VerificationKey{Key: a.Public()}))
	onlyB := keyedJWTService("", mustAccessKeys(t, &model.SigningKey{Key: b}))

	tokenA, tokenB := mintToken(t, signA), mintToken(t, signB)
	for _, s := range []*JWTService{publishB, signB} {
		for _, token := range []string{tokenA, tokenB} {
			if _, err := s.ValidateAccessToken(token); err != nil {
				t.Fatalf("token rejected during rotation: %v", err)
			}
		}
	}
	expectInvalidToken(t, signA, tokenB, "next key before it is published")
	expectInvalidToken(t, onlyB, tokenA, "retired key")
}

// TestJWTServiceRejectsForgedHeaders covers the ways a token could pick its own key
// or algorithm. Each is refused even where the signature itself would check out.
func TestJWTServiceRejectsForgedHeaders(t *testing.T) {
	const secret = "access-secret"
	edKey, ecKey, rsaKey := newEd25519Key(t), newP256Key(t), sharedRSAKey(t)
	keys := mustAccessKeys(t, &model.SigningKey{ID: "ed", Key: edKey},
		model.VerificationKey{ID: "ec", Key: ecKey.Public()},
		model.VerificationKey{ID: "rsa", Key: rsaKey.Public()})
	s := keyedJWTService(secret, keys)

	// Sanity: the real keys work with their own ids.
	for _, token := range []string{
		signedWith(t, jwt.SigningMethodEdDSA, edKey, "ed"),
		signedWith(t, jwt.SigningMethodES256, ecKey, "ec"),
		signedWith(t, jwt.SigningMethodRS256, rsaKey, "rsa"),
		signedWith(t, jwt.SigningMethodHS256, []byte(secret), nil),
	} {
		if _, err := s.ValidateAccessToken(token); err != nil {
			t.Fatalf("genuine token rejected: %v", err)
		}
	}

	rsaPubDER := rsaKey.N.Bytes()
	cases := map[string]string{
		"HS256 with a key id":             signedWith(t, jwt.SigningMethodHS256, []byte(secret), "ed"),
		"HS256 keyed with a public key":   signedWith(t, jwt.SigningMethodHS256, []byte(edKey[32:]) /* its public half */, "ed"),
		"HS256 keyed with an RSA modulus": signedWith(t, jwt.SigningMethodHS256, rsaPubDER, "rsa"),
		"another key's algorithm":         signedWith(t, jwt.SigningMethodES256, ecKey, "ed"),
		"RS256 under the EC key id":       signedWith(t, jwt.SigningMethodRS256, rsaKey, "ec"),
		"unknown key id":                  signedWith(t, jwt.SigningMethodEdDSA, edKey, "missing"),
		"key id that is not a string":     signedWith(t, jwt.SigningMethodEdDSA, edKey, 7),
		"same key id, different key":      signedWith(t, jwt.SigningMethodEdDSA, newEd25519Key(t), "ed"),
		"asymmetric without a key id":     signedWith(t, jwt.SigningMethodEdDSA, edKey, nil),
		"alg none":                        signedWith(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, "ed"),
		"alg none without a key id":       signedWith(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, nil),
		"PS256 with the RSA key":          signedWith(t, jwt.SigningMethodPS256, rsaKey, "rsa"),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) { expectInvalidToken(t, s, token, name) })
	}

	// Without a secret, no token without a key id is accepted, HS256 included.
	noSecret := keyedJWTService("", keys)
	expectInvalidToken(t, noSecret, signedWith(t, jwt.SigningMethodHS256, []byte(secret), nil), "HS256 with no secret configured")

	// A payload changed after signing fails the signature check.
	parts := strings.Split(mintToken(t, s), ".")
	forgedClaims := base64.RawURLEncoding.EncodeToString([]byte(`{"user_id":"x","tenant_id":"other","exp":9999999999}`))
	expectInvalidToken(t, s, parts[0]+"."+forgedClaims+"."+parts[2], "changed payload")
}

func TestJWTServiceWithoutAnyKey(t *testing.T) {
	s := NewJWTService("", time.Minute, time.Hour, nil)
	if _, err := s.GenerateAccessToken(&model.User{ID: "u"}, jwtTestMembership("t")); err == nil {
		t.Fatal("expected an error signing with no key")
	}
	expectInvalidToken(t, s, signedWith(t, jwt.SigningMethodHS256, []byte(""), nil), "token with no key configured")
}

func TestNewAccessKeysRefusesBadKeys(t *testing.T) {
	edKey := newEd25519Key(t)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	smallRSA, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: checks that small keys are refused
	if err != nil {
		t.Fatal(err)
	}
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shortEd := edKey[:40]
	evenExponent := &rsa.PublicKey{N: sharedRSAKey(t).N, E: 65536}
	offCurve := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)} //nolint:staticcheck // SA1019: an off-curve key on purpose; the newer constructors refuse to build one

	for _, tc := range []struct {
		name         string
		signing      *model.SigningKey
		verification []model.VerificationKey
		want         string
	}{
		{"missing signing key", &model.SigningKey{}, nil, "missing"},
		{"typed nil signing key", &model.SigningKey{Key: (*ecdsa.PrivateKey)(nil)}, nil, "missing"},
		{"short ed25519 key", &model.SigningKey{Key: shortEd}, nil, "wrong length"},
		{"P-384", &model.SigningKey{Key: p384}, nil, "P-256"},
		{"RSA 1024", &model.SigningKey{Key: smallRSA}, nil, "at least 2048 bits"},
		{"explicit id with a space", &model.SigningKey{ID: "key one", Key: edKey}, nil, "visible ASCII"},
		{"explicit id too long", &model.SigningKey{ID: strings.Repeat("k", 256), Key: edKey}, nil, "visible ASCII"},
		{"missing verification key", nil, []model.VerificationKey{{ID: "x"}}, "missing"},
		{"private key as verification key", nil, []model.VerificationKey{{Key: edKey}}, "unsupported key type"},
		{"X25519", nil, []model.VerificationKey{{Key: x25519.PublicKey()}}, "unsupported key type"},
		{"even RSA exponent", nil, []model.VerificationKey{{Key: evenExponent}}, "exponent"},
		{"point off the curve", nil, []model.VerificationKey{{Key: offCurve}}, "not a valid P-256 point"},
		{"one id, two keys", &model.SigningKey{ID: "k", Key: edKey}, []model.VerificationKey{{ID: "k", Key: newEd25519Key(t).Public()}}, "already used"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewAccessKeys(tc.signing, tc.verification)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestNewAccessKeysListsEachKeyOnce(t *testing.T) {
	if keys, err := NewAccessKeys(nil, nil); keys != nil || err != nil {
		t.Fatalf("no keys: got %v, %v", keys, err)
	}
	if set := (*AccessKeys)(nil).JSONWebKeySet(); set.Keys == nil || len(set.Keys) != 0 {
		t.Fatalf("nil keys should give an empty, non-nil set: %+v", set)
	}

	signing, other := newEd25519Key(t), newP256Key(t)
	keys := mustAccessKeys(t, &model.SigningKey{Key: signing},
		model.VerificationKey{Key: signing.Public()}, // the signing key again, same thumbprint
		model.VerificationKey{Key: other.Public()},
		model.VerificationKey{Key: other.Public()})
	set := keys.JSONWebKeySet()
	if len(set.Keys) != 2 || set.Keys[0].Algorithm != "EdDSA" || set.Keys[1].Algorithm != "ES256" {
		t.Fatalf("key set = %+v, want the signing key then the P-256 key", set.Keys)
	}
	if got := keys.algorithms(); len(got) != 2 {
		t.Fatalf("algorithms = %v", got)
	}

	encoded, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{`"d"`, `"p"`, `"q"`} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("key set leaks a private member %s: %s", private, encoded)
		}
	}
}

func TestECDSAJWSSignatureRefusesMalformedInput(t *testing.T) {
	for name, der := range map[string][]byte{
		"empty":         nil,
		"not DER":       []byte("not a signature"),
		"trailing data": append([]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, 0x00),
		"zero r":        {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01},
		"negative s":    {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0xff},
		"r too long":    append([]byte{0x30, 0x26, 0x02, 0x21, 0x01}, append(make([]byte, 32), 0x02, 0x01, 0x01)...),
	} {
		if _, err := ecdsaJWSSignature(der, 32); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}
	sig, err := ecdsaJWSSignature([]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}, 32)
	if err != nil || len(sig) != 64 || sig[31] != 1 || sig[63] != 2 {
		t.Fatalf("well-formed signature: %x, %v", sig, err)
	}
}
