// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "crypto"

// SigningKey is an asymmetric private key that signs access tokens. The key's type
// picks the algorithm:
//
//   - ed25519.PrivateKey: EdDSA
//   - *ecdsa.PrivateKey on P-256: ES256
//   - *rsa.PrivateKey of at least 2048 bits: RS256
//
// Any other crypto.Signer whose Public() is one of those public key types works
// too, such as a key held in a KMS or an HSM.
type SigningKey struct {
	// ID is stamped in each token's "kid" header and published in the key set:
	// 1 to 255 visible ASCII characters. Empty uses the public key's RFC 7638
	// thumbprint, so the same key always gets the same id.
	ID  string
	Key crypto.Signer
}

// VerificationKey is a public key accepted when validating access tokens, beside
// the signing key's own: a key the application is about to sign with, or one it
// signed with until recently. Key is an ed25519.PublicKey, an *ecdsa.PublicKey on
// P-256 or an *rsa.PublicKey of at least 2048 bits; ID follows SigningKey.ID.
type VerificationKey struct {
	ID  string
	Key crypto.PublicKey
}

// JSONWebKey is one public key in a JSON Web Key Set (RFC 7517). Ed25519 keys use
// kty "OKP" (RFC 8037) with crv and x; P-256 keys use kty "EC" with crv, x and y;
// RSA keys use kty "RSA" with n and e.
type JSONWebKey struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	Curve     string `json:"crv,omitempty"`
	X         string `json:"x,omitempty"`
	Y         string `json:"y,omitempty"`
	N         string `json:"n,omitempty"`
	E         string `json:"e,omitempty"`
}

// JSONWebKeySet is the public half of the access-token keys, in the format other
// services and API gateways read from a jwks_uri such as /.well-known/jwks.json.
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}
