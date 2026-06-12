// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"strings"
	"testing"
)

func TestRepositoryQualifiesConfiguredSchema(t *testing.T) {
	repo := NewWithSchema(nil, nil, "custom_identity")

	query := repo.q("SELECT * FROM {{schema}}.users WHERE id = $1")
	if !strings.Contains(query, `"custom_identity".users`) {
		t.Fatalf("expected configured schema in query, got %q", query)
	}
	if strings.Contains(query, "{{schema}}") {
		t.Fatalf("expected schema placeholder to be replaced, got %q", query)
	}
}

func TestIsIdentifier(t *testing.T) {
	valid := []string{"authkit", "identity2", "_identity"}
	for _, value := range valid {
		if !IsIdentifier(value) {
			t.Fatalf("expected %q to be valid", value)
		}
	}

	invalid := []string{"", "2identity", "identity.schema", "identity;drop", "identity-name"}
	for _, value := range invalid {
		if IsIdentifier(value) {
			t.Fatalf("expected %q to be invalid", value)
		}
	}
}
