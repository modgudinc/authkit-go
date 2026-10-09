// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/modgudinc/authkit-go/model"
)

func pemBlock(blockType string, der []byte, headers map[string]string) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Headers: headers, Bytes: der})
}

func samePublic(a, b crypto.PublicKey) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(b)
}

func TestParseKeyPEM(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := func(b []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	for _, tc := range []struct {
		name string
		pem  []byte
		want crypto.Signer
	}{
		{"PKCS #8 Ed25519", pemBlock("PRIVATE KEY", der(x509.MarshalPKCS8PrivateKey(edKey)), nil), edKey},
		{"PKCS #8 P-256", pemBlock("PRIVATE KEY", der(x509.MarshalPKCS8PrivateKey(ecKey)), nil), ecKey},
		{"SEC 1 P-256", pemBlock("EC PRIVATE KEY", der(x509.MarshalECPrivateKey(ecKey)), nil), ecKey},
		{"PKCS #1 RSA", pemBlock("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey), nil), rsaKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePrivateKeyPEM(append(tc.pem, '\n'))
			if err != nil {
				t.Fatalf("parse private key: %v", err)
			}
			if !samePublic(got.Public(), tc.want.Public()) {
				t.Fatal("parsed a different key")
			}
		})
	}

	for _, tc := range []struct {
		name string
		pem  []byte
		want crypto.PublicKey
	}{
		{"PKIX Ed25519", pemBlock("PUBLIC KEY", der(x509.MarshalPKIXPublicKey(edKey.Public())), nil), edKey.Public()},
		{"PKIX P-256", pemBlock("PUBLIC KEY", der(x509.MarshalPKIXPublicKey(ecKey.Public())), nil), ecKey.Public()},
		{"PKCS #1 RSA", pemBlock("RSA PUBLIC KEY", x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey), nil), &rsaKey.PublicKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePublicKeyPEM(tc.pem)
			if err != nil {
				t.Fatalf("parse public key: %v", err)
			}
			if !samePublic(got, tc.want) {
				t.Fatal("parsed a different key")
			}
		})
	}

	edPEM := pemBlock("PRIVATE KEY", der(x509.MarshalPKCS8PrivateKey(edKey)), nil)
	for name, data := range map[string][]byte{
		"empty":             nil,
		"not PEM":           []byte("ed25519 key"),
		"two keys":          append(append([]byte{}, edPEM...), edPEM...),
		"encrypted":         pemBlock("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey), map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00000000000000000000000000000000"}),
		"PKCS #8 encrypted": pemBlock("ENCRYPTED PRIVATE KEY", []byte{1, 2, 3}, nil),
		"public key":        pemBlock("PUBLIC KEY", der(x509.MarshalPKIXPublicKey(edKey.Public())), nil),
		"malformed DER":     pemBlock("PRIVATE KEY", []byte("not DER"), nil),
	} {
		if _, err := ParsePrivateKeyPEM(data); err == nil {
			t.Fatalf("private %s: expected an error", name)
		} else if strings.Contains(err.Error(), "not DER") {
			t.Fatalf("private %s: error echoes the input: %v", name, err)
		}
	}
	for name, data := range map[string][]byte{
		"private key":   edPEM,
		"certificate":   pemBlock("CERTIFICATE", []byte{1, 2, 3}, nil),
		"malformed DER": pemBlock("PUBLIC KEY", []byte("not DER"), nil),
		"trailing data": append(pemBlock("PUBLIC KEY", der(x509.MarshalPKIXPublicKey(edKey.Public())), nil), []byte("junk")...),
	} {
		if _, err := ParsePublicKeyPEM(data); err == nil {
			t.Fatalf("public %s: expected an error", name)
		}
	}
}

func TestNewWithSigningKeys(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// A signing key replaces the access secret, which then becomes optional.
	config := validTestConfig()
	config.JWTConfig.AccessSecret = ""
	config.JWTConfig.SigningKey = &SigningKey{ID: "primary", Key: edKey}
	config.JWTConfig.VerificationKeys = []VerificationKey{{Key: ecKey.Public()}}
	kit, err := New(config)
	if err != nil {
		t.Fatalf("new with a signing key: %v", err)
	}
	set := kit.JSONWebKeySet()
	if len(set.Keys) != 2 || set.Keys[0].KeyID != "primary" || set.Keys[0].Algorithm != "EdDSA" || set.Keys[1].Algorithm != "ES256" {
		t.Fatalf("key set = %+v", set.Keys)
	}

	// The JWT service the kit hands out signs with the key and checks its tokens.
	token, err := kit.JWTService().GenerateAccessToken(&model.User{ID: "user-1", Email: "u@example.com"},
		&model.Membership{TenantID: "tenant-a", Status: model.MembershipActive})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := kit.JWTService().ValidateAccessToken(token); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// A kit with only the secret publishes an empty set, never the secret.
	hsKit, err := New(validTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(hsKit.JSONWebKeySet())
	if err != nil || string(encoded) != `{"keys":[]}` {
		t.Fatalf("HS256 key set = %s, %v", encoded, err)
	}

	smallRSA, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: checks that small keys are refused
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"neither secret nor key", func(c *Config) { c.JWTConfig.AccessSecret = "" }, "signing secret or signing key"},
		{"verification keys alone", func(c *Config) {
			c.JWTConfig.AccessSecret = ""
			c.JWTConfig.VerificationKeys = []VerificationKey{{Key: ecKey.Public()}}
		}, "signing secret or signing key"},
		{"short secret beside a key", func(c *Config) {
			c.JWTConfig.AccessSecret = "short"
			c.JWTConfig.SigningKey = &SigningKey{Key: edKey}
		}, "at least 32 bytes"},
		{"small RSA key", func(c *Config) { c.JWTConfig.SigningKey = &SigningKey{Key: smallRSA} }, "at least 2048 bits"},
		{"bad verification key", func(c *Config) {
			c.JWTConfig.VerificationKeys = []VerificationKey{{Key: "not a key"}}
		}, "unsupported key type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := validTestConfig()
			tc.mutate(&config)
			_, err := New(config)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}
