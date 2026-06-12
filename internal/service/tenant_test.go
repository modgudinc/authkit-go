// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import "testing"

func TestTenantServiceValidateDomain(t *testing.T) {
	service := NewTenantService(nil, nil)

	for _, domain := range []string{"example.com", "mail.example.com", "api.v2.example.co"} {
		if err := service.validateDomain(domain); err != nil {
			t.Fatalf("expected %q to be valid: %v", domain, err)
		}
	}

	for _, domain := range []string{"", "localhost", "-example.com", "example", "example.c", "example..com"} {
		if err := service.validateDomain(domain); err == nil {
			t.Fatalf("expected %q to be invalid", domain)
		}
	}
}

func TestTenantServiceExtractDomain(t *testing.T) {
	service := NewTenantService(nil, nil)

	tests := map[string]string{
		"user@example.com":       "example.com",
		"USER@Mail.Example.COM":  "mail.example.com",
		"invalid":                "",
		"too@many@example.com":   "",
		"missing-domain@":        "",
		"missing-local@example":  "example",
		"plus+tag@example.co.uk": "example.co.uk",
	}

	for email, want := range tests {
		got := service.extractDomain(email)
		if got != want {
			t.Fatalf("extractDomain(%q) = %q, want %q", email, got, want)
		}
	}
}
