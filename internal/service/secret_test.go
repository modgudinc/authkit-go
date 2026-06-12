// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestSecretServiceEncryptDecryptRoundTrip(t *testing.T) {
	service := NewSecretService(nil, []byte("0123456789abcdef0123456789abcdef"), nil)

	encrypted, err := service.encrypt("sk-test-secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if encrypted == "" || encrypted == "sk-test-secret" {
		t.Fatalf("unexpected encrypted value: %q", encrypted)
	}

	plain, err := service.decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if plain != "sk-test-secret" {
		t.Fatalf("plain = %q, want original secret", plain)
	}
}

func TestSecretServiceDecryptRejectsInvalidCiphertext(t *testing.T) {
	service := NewSecretService(nil, []byte("0123456789abcdef0123456789abcdef"), nil)

	for _, input := range []string{"not-base64", "c2hvcnQ="} {
		if _, err := service.decrypt(input); err == nil {
			t.Fatalf("expected %q to fail decrypt", input)
		}
	}

	encrypted, err := service.encrypt("sk-test-secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Flip a guaranteed-different byte inside the ciphertext body so the GCM auth
	// check always fails. (Appending fixed base64 chars is a no-op whenever the
	// random nonce already ends in those chars — ~1 in 3500 runs.)
	raw, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatalf("decode encrypted: %v", err)
	}
	raw[len(raw)-1] ^= 0xFF
	tampered := base64.StdEncoding.EncodeToString(raw)
	if _, err := service.decrypt(tampered); err == nil {
		t.Fatal("expected tampered ciphertext to fail decrypt")
	}
}

func TestSecretServiceRejectsInvalidKeyLength(t *testing.T) {
	service := NewSecretService(nil, []byte("too-short"), nil)

	if _, err := service.encrypt("secret"); err == nil {
		t.Fatal("expected invalid key length to fail encrypt")
	}
	if _, err := service.decrypt("c2hvcnQ="); err == nil {
		t.Fatal("expected invalid key length to fail decrypt")
	}
}

func TestMaskValue(t *testing.T) {
	tests := map[string]string{
		"short":              "************",
		"sk-abc123def456":    "sk-************f456",
		"cur_1234567890abcd": "cur_************abcd",
		"plainsecret":        "************cret",
	}

	for input, want := range tests {
		got := maskValue(input)
		if got != want {
			t.Fatalf("maskValue(%q) = %q, want %q", input, got, want)
		}
		if len(input) >= 8 && strings.Contains(got, input[:len(input)-4]) {
			t.Fatalf("masked value leaked too much input: %q", got)
		}
	}
}
