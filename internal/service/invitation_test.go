// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import "testing"

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
