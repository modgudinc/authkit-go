// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modgudinc/authkit-go/model"
)

// minRSABits is the smallest RSA modulus accepted for access-token keys.
const minRSABits = 2048

const (
	algEdDSA = "EdDSA"
	algES256 = "ES256"
	algRS256 = "RS256"
)

// accessKey is one public key that verifies access tokens.
type accessKey struct {
	id     string
	alg    string
	public crypto.PublicKey
	jwk    model.JSONWebKey
}

// AccessKeys holds the asymmetric access-token keys: at most one that signs, and
// every public key that verifies, by key id. Build it with NewAccessKeys.
type AccessKeys struct {
	signer  crypto.Signer
	signing *accessKey // nil: tokens are signed with the HS256 secret
	byID    map[string]*accessKey
	ordered []*accessKey // the signing key first, then the verification keys
}

// NewAccessKeys checks the configured keys and derives their ids and algorithms.
// It returns nil when there are none.
func NewAccessKeys(signing *model.SigningKey, verification []model.VerificationKey) (*AccessKeys, error) {
	if signing == nil && len(verification) == 0 {
		return nil, nil
	}
	keys := &AccessKeys{byID: map[string]*accessKey{}}
	if signing != nil {
		if err := checkPrivateKey(signing.Key); err != nil {
			return nil, fmt.Errorf("signing key: %w", err)
		}
		key, err := newAccessKey(signing.ID, signing.Key.Public())
		if err != nil {
			return nil, fmt.Errorf("signing key: %w", err)
		}
		keys.signer = signing.Key
		keys.signing = key
		keys.add(key)
	}
	for i, v := range verification {
		if v.Key == nil {
			return nil, fmt.Errorf("verification key %d: key is missing", i)
		}
		key, err := newAccessKey(v.ID, v.Key)
		if err != nil {
			return nil, fmt.Errorf("verification key %d: %w", i, err)
		}
		if existing := keys.byID[key.id]; existing != nil {
			// Listing the same key twice (say, the signing key's public half) is
			// harmless; one id for two different keys would make lookups ambiguous.
			if !samePublicKey(existing.public, key.public) {
				return nil, fmt.Errorf("verification key %d: key id %q is already used by a different key", i, key.id)
			}
			continue
		}
		keys.add(key)
	}
	return keys, nil
}

func (k *AccessKeys) add(key *accessKey) {
	k.byID[key.id] = key
	k.ordered = append(k.ordered, key)
}

// algorithms returns the JWS algorithms of the keys, each once.
func (k *AccessKeys) algorithms() []string {
	var algs []string
	seen := map[string]bool{}
	for _, key := range k.ordered {
		if !seen[key.alg] {
			seen[key.alg] = true
			algs = append(algs, key.alg)
		}
	}
	return algs
}

// JSONWebKeySet returns the public keys, the signing key first.
func (k *AccessKeys) JSONWebKeySet() model.JSONWebKeySet {
	set := model.JSONWebKeySet{Keys: []model.JSONWebKey{}}
	if k == nil {
		return set
	}
	for _, key := range k.ordered {
		set.Keys = append(set.Keys, key.jwk)
	}
	return set
}

// sign signs a JWS signing input with the signing key, in the signature encoding
// of its algorithm. The signer's own Sign is used rather than golang-jwt's, so any
// crypto.Signer works, including one backed by a KMS or an HSM.
func (k *AccessKeys) sign(signingInput string) ([]byte, error) {
	msg := []byte(signingInput)
	switch k.signing.alg {
	case algEdDSA:
		return k.signer.Sign(rand.Reader, msg, crypto.Hash(0))
	case algES256:
		digest := sha256.Sum256(msg)
		der, err := k.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return ecdsaJWSSignature(der, 32)
	case algRS256:
		digest := sha256.Sum256(msg)
		return k.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
	return nil, fmt.Errorf("unsupported signing algorithm %s", k.signing.alg)
}

// ecdsaJWSSignature converts the ASN.1 DER signature crypto.Signer returns for an
// ECDSA key into the fixed-size R || S form JWS uses (RFC 7518 section 3.4).
func ecdsaJWSSignature(der []byte, size int) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil ||
		sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.BitLen() > size*8 || sig.S.BitLen() > size*8 {
		return nil, errors.New("signer returned a malformed ECDSA signature")
	}
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}

// checkPrivateKey refuses a missing or malformed in-memory private key before its
// Public method runs (an ed25519.PrivateKey of the wrong length panics there).
// Other crypto.Signer implementations are trusted to report their own public key.
func checkPrivateKey(key crypto.Signer) error {
	switch k := key.(type) {
	case nil:
		return errors.New("key is missing")
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return errors.New("ed25519 private key has the wrong length")
		}
	case *ed25519.PrivateKey:
		if k == nil || len(*k) != ed25519.PrivateKeySize {
			return errors.New("ed25519 private key has the wrong length")
		}
	case *ecdsa.PrivateKey:
		if k == nil {
			return errors.New("key is missing")
		}
	case *rsa.PrivateKey:
		if k == nil {
			return errors.New("key is missing")
		}
		if err := k.Validate(); err != nil {
			return errors.New("RSA private key is inconsistent")
		}
	}
	return nil
}

// newAccessKey derives a public key's algorithm, JWK and key id, refusing key
// types, curves and sizes authkit does not sign or accept tokens with.
func newAccessKey(id string, public crypto.PublicKey) (*accessKey, error) {
	alg, jwk, err := publicJWK(public)
	if err != nil {
		return nil, err
	}
	if id == "" {
		id = jwkThumbprint(jwk)
	} else if !validKeyID(id) {
		return nil, errors.New("key id must be 1 to 255 visible ASCII characters")
	}
	jwk.KeyID = id
	jwk.Use = "sig"
	jwk.Algorithm = alg
	return &accessKey{id: id, alg: alg, public: public, jwk: jwk}, nil
}

func publicJWK(public crypto.PublicKey) (string, model.JSONWebKey, error) {
	switch k := public.(type) {
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return "", model.JSONWebKey{}, errors.New("ed25519 public key has the wrong length")
		}
		return algEdDSA, model.JSONWebKey{KeyType: "OKP", Curve: "Ed25519", X: b64(k)}, nil
	case *ecdsa.PublicKey:
		if k == nil || k.Curve != elliptic.P256() {
			return "", model.JSONWebKey{}, errors.New("ECDSA keys must use the P-256 curve")
		}
		point, err := k.Bytes() // 0x04 || X || Y; fails for a point not on the curve
		if err != nil {
			return "", model.JSONWebKey{}, errors.New("ECDSA public key is not a valid P-256 point")
		}
		return algES256, model.JSONWebKey{KeyType: "EC", Curve: "P-256", X: b64(point[1:33]), Y: b64(point[33:])}, nil
	case *rsa.PublicKey:
		if k == nil || k.N == nil || k.N.BitLen() < minRSABits {
			return "", model.JSONWebKey{}, fmt.Errorf("RSA keys must be at least %d bits", minRSABits)
		}
		if k.E < 3 || k.E%2 == 0 {
			return "", model.JSONWebKey{}, errors.New("RSA public exponent is invalid")
		}
		return algRS256, model.JSONWebKey{KeyType: "RSA", N: b64(k.N.Bytes()), E: b64(big.NewInt(int64(k.E)).Bytes())}, nil
	}
	return "", model.JSONWebKey{}, fmt.Errorf("unsupported key type %T: use Ed25519, ECDSA P-256 or RSA", public)
}

// jwkThumbprint is the RFC 7638 thumbprint of a public JWK: the base64url SHA-256
// of its required members, in lexicographic order, with no whitespace. Struct
// fields are declared in that order, and base64url values need no JSON escaping.
func jwkThumbprint(jwk model.JSONWebKey) string {
	var members any
	switch jwk.KeyType {
	case "OKP":
		members = struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
		}{jwk.Curve, jwk.KeyType, jwk.X}
	case "EC":
		members = struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{jwk.Curve, jwk.KeyType, jwk.X, jwk.Y}
	default:
		members = struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}{jwk.E, jwk.KeyType, jwk.N}
	}
	canonical, _ := json.Marshal(members) // plain strings: cannot fail
	sum := sha256.Sum256(canonical)
	return b64(sum[:])
}

func validKeyID(id string) bool {
	if len(id) > 255 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x21 || id[i] > 0x7e {
			return false
		}
	}
	return id != ""
}

func samePublicKey(a, b crypto.PublicKey) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(b)
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// verificationKey returns the key a token's header names, refusing a key id that
// is not a string or names no key, and an algorithm other than the key's own.
func (k *AccessKeys) verificationKey(token *jwt.Token, kid any) (crypto.PublicKey, error) {
	id, ok := kid.(string)
	if !ok {
		return nil, errors.New("token key id is not a string")
	}
	if k == nil {
		return nil, errors.New("token names a key id but no keys are configured")
	}
	key := k.byID[id]
	if key == nil {
		return nil, errors.New("token names an unknown key id")
	}
	if token.Method.Alg() != key.alg {
		return nil, errors.New("token algorithm does not match its key")
	}
	return key.public, nil
}
