// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
	"testing"
)

const (
	testSecretKey = "0123456789abcdef0123456789abcdef"
	testTenant    = "acme.com"
	testKeyName   = "openai"
)

func TestSecretServiceEncryptDecryptRoundTrip(t *testing.T) {
	svc := NewSecretService(nil, []byte(testSecretKey), nil)

	encrypted, err := svc.encrypt("sk-test-secret", testTenant, testKeyName)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if encrypted == "" || encrypted == "sk-test-secret" {
		t.Fatalf("unexpected encrypted value: %q", encrypted)
	}
	if !strings.HasPrefix(encrypted, secretCipherV1Prefix) {
		t.Fatalf("encrypted value missing v1 prefix: %q", encrypted)
	}

	plain, err := svc.decrypt(encrypted, testTenant, testKeyName)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if plain != "sk-test-secret" {
		t.Fatalf("plain = %q, want original secret", plain)
	}
}

// TestSecretServiceDecryptRejectsWrongContext verifies the AAD binds ciphertext
// to its (tenant, key): decrypting under a different context fails authentication.
func TestSecretServiceDecryptRejectsWrongContext(t *testing.T) {
	svc := NewSecretService(nil, []byte(testSecretKey), nil)

	encrypted, err := svc.encrypt("sk-test-secret", testTenant, testKeyName)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := svc.decrypt(encrypted, "other.com", testKeyName); err == nil {
		t.Fatal("expected decrypt under a different tenant to fail")
	}
	if _, err := svc.decrypt(encrypted, testTenant, "anthropic"); err == nil {
		t.Fatal("expected decrypt under a different key to fail")
	}
}

// TestSecretServiceDecryptsLegacyCiphertext verifies backward compatibility:
// ciphertext written before AAD binding (bare base64, no v1 prefix, no AAD) still
// decrypts under the new code.
func TestSecretServiceDecryptsLegacyCiphertext(t *testing.T) {
	key := []byte(testSecretKey)
	svc := NewSecretService(nil, key, nil)

	// Hand-roll a legacy blob: nonce || Seal(..., nil AAD), bare base64, no prefix.
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	legacy := base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte("legacy-secret"), nil))

	plain, err := svc.decrypt(legacy, testTenant, testKeyName)
	if err != nil {
		t.Fatalf("decrypt legacy: %v", err)
	}
	if plain != "legacy-secret" {
		t.Fatalf("plain = %q, want legacy-secret", plain)
	}
}

func TestSecretServiceDecryptRejectsInvalidCiphertext(t *testing.T) {
	svc := NewSecretService(nil, []byte(testSecretKey), nil)

	for _, input := range []string{"not-base64", "c2hvcnQ=", "v1:not-base64"} {
		if _, err := svc.decrypt(input, testTenant, testKeyName); err == nil {
			t.Fatalf("expected %q to fail decrypt", input)
		}
	}

	encrypted, err := svc.encrypt("sk-test-secret", testTenant, testKeyName)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Flip a guaranteed-different byte inside the ciphertext body so the GCM auth
	// check always fails. Strip the v1 prefix first so the remainder is base64.
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encrypted, secretCipherV1Prefix))
	if err != nil {
		t.Fatalf("decode encrypted: %v", err)
	}
	raw[len(raw)-1] ^= 0xFF
	tampered := secretCipherV1Prefix + base64.StdEncoding.EncodeToString(raw)
	if _, err := svc.decrypt(tampered, testTenant, testKeyName); err == nil {
		t.Fatal("expected tampered ciphertext to fail decrypt")
	}
}

func TestSecretServiceRejectsInvalidKeyLength(t *testing.T) {
	svc := NewSecretService(nil, []byte("too-short"), nil)

	if _, err := svc.encrypt("secret", testTenant, testKeyName); err == nil {
		t.Fatal("expected invalid key length to fail encrypt")
	}
	if _, err := svc.decrypt("c2hvcnQ=", testTenant, testKeyName); err == nil {
		t.Fatal("expected invalid key length to fail decrypt")
	}
}

func TestMaskValue(t *testing.T) {
	tests := map[string]string{
		"short":              "************",         // < 12: fully masked
		"plainsecret":        "************",         // 11 chars: now fully masked
		"sk-abc123def456":    "sk-************f456",  // 15 chars: partial reveal
		"cur_1234567890abcd": "cur_************abcd", // 18 chars: partial reveal
	}

	for input, want := range tests {
		got := maskValue(input)
		if got != want {
			t.Fatalf("maskValue(%q) = %q, want %q", input, got, want)
		}
		if len(input) >= 12 && strings.Contains(got, input[:len(input)-4]) {
			t.Fatalf("masked value leaked too much input: %q", got)
		}
	}
}
