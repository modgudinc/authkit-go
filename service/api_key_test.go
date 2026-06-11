// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"strings"
	"testing"
	"time"
)

func TestAPIKeyServiceGenerateSecureKeyAndValidateFormat(t *testing.T) {
	service := NewAPIKeyService(nil, "hmac-secret", nil)

	key, err := service.generateSecureKey()
	if err != nil {
		t.Fatalf("generate secure key: %v", err)
	}
	if len(key) != 40 {
		t.Fatalf("key length = %d, want 40", len(key))
	}
	if !strings.HasPrefix(key, "sk_live_") {
		t.Fatalf("key prefix mismatch: %s", key)
	}
	if err := service.validateKeyFormat(key); err != nil {
		t.Fatalf("generated key should validate: %v", err)
	}
}

func TestAPIKeyServiceValidateKeyFormatRejectsInvalidValues(t *testing.T) {
	service := NewAPIKeyService(nil, "hmac-secret", nil)

	tests := []string{
		"",
		"sk_test_abcdefghijklmnopqrstuvwxyz123456",
		"sk_live_short",
		"sk_live_abcdefghijklmnopqrstuvwxyz12345!",
	}

	for _, test := range tests {
		if err := service.validateKeyFormat(test); err == nil {
			t.Fatalf("expected %q to be invalid", test)
		}
	}
}

func TestAPIKeyServiceComputeHMAC(t *testing.T) {
	service := NewAPIKeyService(nil, "hmac-secret", nil)

	hash1 := service.computeHMAC("sk_live_abcdefghijklmnopqrstuvwxyz123456")
	hash2 := service.computeHMAC("sk_live_abcdefghijklmnopqrstuvwxyz123456")
	hash3 := service.computeHMAC("sk_live_abcdefghijklmnopqrstuvwxyz123457")

	if hash1 == "" {
		t.Fatal("hash should not be empty")
	}
	if hash1 != hash2 {
		t.Fatal("same API key should produce the same HMAC")
	}
	if hash1 == hash3 {
		t.Fatal("different API keys should produce different HMACs")
	}
}

func TestAPIKeyServiceParseExpiration(t *testing.T) {
	service := NewAPIKeyService(nil, "hmac-secret", nil)

	tests := map[string]time.Duration{
		"30d": 30 * 24 * time.Hour,
		"6M":  6 * 30 * 24 * time.Hour,
		"1y":  365 * 24 * time.Hour,
	}

	for input, want := range tests {
		got, err := service.parseExpiration(input)
		if err != nil {
			t.Fatalf("parse %q: %v", input, err)
		}
		if got != want {
			t.Fatalf("parse %q = %s, want %s", input, got, want)
		}
	}

	for _, input := range []string{"", "d", "xd", "10h"} {
		if _, err := service.parseExpiration(input); err == nil {
			t.Fatalf("expected %q to be invalid", input)
		}
	}
}
