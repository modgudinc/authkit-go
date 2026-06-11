// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"testing"

	"github.com/google/uuid"
)

func TestParseUserID(t *testing.T) {
	userID := uuid.Must(uuid.NewV7())

	parsed, err := parseUserID(userID.String())
	if err != nil {
		t.Fatalf("parse user ID: %v", err)
	}
	if parsed != userID {
		t.Fatalf("parsed = %s, want %s", parsed, userID)
	}

	if _, err := parseUserID("not-a-uuid"); err == nil {
		t.Fatal("expected invalid UUID to fail")
	}
}
