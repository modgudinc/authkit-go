// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/modgudinc/authkit-go/model"
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

// TestSecretServiceRejectsPrefixlessCiphertext verifies the anti-downgrade
// hardening: a prefix-less blob (the old "legacy" format, encrypted without AAD)
// is rejected rather than decrypted. Otherwise an attacker who could write the
// column could strip the v1 marker to bypass the (tenant, key) context binding.
func TestSecretServiceRejectsPrefixlessCiphertext(t *testing.T) {
	key := []byte(testSecretKey)
	svc := NewSecretService(nil, key, nil)

	// Hand-roll a prefix-less blob: nonce || Seal(..., nil AAD), bare base64.
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
	prefixless := base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte("legacy-secret"), nil))

	if _, err := svc.decrypt(prefixless, testTenant, testKeyName); err == nil {
		t.Fatal("expected prefix-less ciphertext to be rejected")
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

// TestSecretServiceMissingKeyReturnsSentinel verifies a misconfigured (or absent)
// encryption key surfaces as a matchable ErrSecretEncryptionKeyMissing at the
// first secret operation, not as an opaque internal error.
func TestSecretServiceMissingKeyReturnsSentinel(t *testing.T) {
	ctx := context.Background()
	svc := NewSecretService(nil, []byte("too-short"), nil) // not 32 bytes

	_, saveErr := svc.Save(ctx, model.SaveSecretRequest{TenantID: testTenant, Key: testKeyName, PlainValue: "v"})
	if !errors.Is(saveErr, model.ErrSecretEncryptionKeyMissing) {
		t.Fatalf("Save: expected ErrSecretEncryptionKeyMissing, got %v", saveErr)
	}

	_, getErr := svc.Get(ctx, testTenant, testKeyName)
	if !errors.Is(getErr, model.ErrSecretEncryptionKeyMissing) {
		t.Fatalf("Get: expected ErrSecretEncryptionKeyMissing, got %v", getErr)
	}
}

func TestMaskValue(t *testing.T) {
	tests := map[string]string{
		"short":              "************",         // < 12: fully masked
		"plainsecret":        "************",         // 11 chars: now fully masked
		"sk-abc123def456":    "sk-************f456",  // 15 chars: partial reveal
		"cur_1234567890abcd": "cur_************abcd", // 18 chars: partial reveal
		// A delimiter that sits LATE in the string is not a type tag; revealing
		// everything up to it would leak the bulk of the secret, so only the last 4
		// chars are revealed. (Regression: the old guard could leak the leading run.)
		"abcdefghi-jklm":  "************jklm", // 14 chars, first delimiter at index 9
		"abcdefghijklmno": "************lmno", // 15 chars, no delimiter at all
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
