//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"database/sql"
	"testing"

	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/model"
)

// SessionInfo.IPAddress often comes straight from an http.Request: RemoteAddr is
// "host:port", and X-Forwarded-For can be a list. A sign-in stores the address it
// can parse instead of failing on the INET column.
func TestLoginStoresTheAddressItCanParse(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { applyMigration(t, db, "000001_identity_schema.down.sql"); _ = db.Close() })
	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyIdentitySchema(t, db)
	repo := repository.New(db, db)
	userID := createTenantAndUser(t, ctx, &repo, "address.test")
	k := newIntegrationAuthKit(t, db)

	for in, want := range map[string]sql.NullString{
		"203.0.113.7:51234":     {String: "203.0.113.7", Valid: true},
		"[2001:db8::7]:51234":   {String: "2001:db8::7", Valid: true},
		"203.0.113.7, 10.0.0.1": {},
	} {
		resp, err := k.AuthService().Login(ctx, model.LoginRequest{
			Email: "admin@address.test", Password: "ValidPass1!", TenantID: "address.test",
			SessionInfo: &model.SessionInfo{IPAddress: in},
		})
		if err != nil {
			t.Fatalf("login from %q: %v", in, err)
		}
		var got sql.NullString
		if err := db.QueryRow(`SELECT host(ip_address) FROM authkit.refresh_tokens WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`, userID).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("login from %q stored %v, want %v", in, got, want)
		}
		if err := k.AuthService().Logout(ctx, resp.RefreshToken); err != nil {
			t.Fatal(err)
		}
	}
}
