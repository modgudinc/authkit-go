// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"testing"

	"github.com/modgudinc/authkit-go/model"
)

func TestCreateInvitationRejectsInvalidInput(t *testing.T) {
	// Validation runs before any repository call, so a nil repo is fine here.
	service := NewInvitationService(nil, nil)

	excessiveUses := MaxInvitationUses + 1
	cases := map[string]model.CreateInvitationRequest{
		"empty email":      {TenantID: "acme.test", Email: ""},
		"malformed email":  {TenantID: "acme.test", Email: "not-an-email"},
		"empty domain":     {TenantID: "acme.test", Email: "user@"},
		"whitespace local": {TenantID: "acme.test", Email: "a b@acme.test"},
		"excessive uses":   {TenantID: "acme.test", Email: "user@acme.test", MaxUses: &excessiveUses},
	}

	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := service.Create(context.Background(), req); err == nil {
				t.Fatal("expected a validation error, got nil")
			}
		})
	}
}

func TestInvitationServiceGenerateInvitationCode(t *testing.T) {
	service := NewInvitationService(nil, nil)

	code, err := service.generateInvitationCode()
	if err != nil {
		t.Fatalf("generate invitation code: %v", err)
	}
	if len(code) != InvitationCodeLength {
		t.Fatalf("code length = %d, want %d", len(code), InvitationCodeLength)
	}

	for _, ch := range code {
		found := false
		for _, allowed := range InvitationCodeCharset {
			if ch == allowed {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("code contains invalid character %q", ch)
		}
	}
}

func TestMaskCode(t *testing.T) {
	tests := map[string]string{
		"":       "***",
		"ABC":    "***",
		"ABCD":   "***",
		"ABCDE":  "ABCD***",
		"ABC123": "ABC1***",
	}

	for input, want := range tests {
		got := maskCode(input)
		if got != want {
			t.Fatalf("maskCode(%q) = %q, want %q", input, got, want)
		}
	}
}
