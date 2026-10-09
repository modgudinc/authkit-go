//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	authkit "github.com/modgudinc/authkit-go"
	"github.com/modgudinc/authkit-go/model"
)

// TestStorageFailureIsNotBadCredentials checks that a sign-in whose lookup fails
// reports an internal error, not wrong credentials, so an application answers 500
// during an outage or before a migration instead of telling people their password or
// key is wrong.
func TestStorageFailureIsNotBadCredentials(t *testing.T) {
	ctx := context.Background()
	wellFormedKey := "sk_live_" + strings.Repeat("a", 32)

	t.Run("migration missing", func(t *testing.T) {
		db := openTestDB(t)
		applyMigration(t, db, "000001_identity_schema.down.sql")
		t.Cleanup(func() {
			applyMigration(t, db, "000001_identity_schema.down.sql")
			_ = db.Close()
		})
		// Without 000005, every user query fails on users.email_verified_at.
		applyMigration(t, db, "000001_identity_schema.up.sql")
		k := newIntegrationAuthKit(t, db)

		_, err := k.AuthService().LoginByEmail(ctx, model.LoginByEmailRequest{Email: "someone@example.test", Password: "Whatever1!"})
		assertInternal(t, "LoginByEmail", err, authkit.ErrInvalidCredentials)
	})

	t.Run("database unreachable", func(t *testing.T) {
		db := openTestDB(t)
		k := newIntegrationAuthKit(t, db)
		_ = db.Close()

		_, err := k.AuthService().Login(ctx, model.LoginRequest{Email: "someone@example.test", Password: "Whatever1!", TenantID: "acme.test"})
		assertInternal(t, "Login", err, authkit.ErrInvalidCredentials)
		_, err = k.APIKeyService().Validate(ctx, wellFormedKey)
		assertInternal(t, "APIKeyService.Validate", err, authkit.ErrInvalidAPIKey)
	})
}

func assertInternal(t *testing.T, op string, err, notThis error) {
	t.Helper()
	if !errors.Is(err, authkit.ErrInternal) || errors.Is(err, notThis) {
		t.Fatalf("%s: expected ErrInternal and not %v, got %v", op, notThis, err)
	}
}
