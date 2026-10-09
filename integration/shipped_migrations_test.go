//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"database/sql"
	"io/fs"
	"testing"

	authkit "github.com/modgudinc/authkit-go"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/model"
)

// TestShippedMigrationsRunInOrder applies every migration authkit.Migrations
// returns, in version order as golang-migrate does, for the default schema and for
// a custom one whose mixed-case name must be quoted. It then signs in through the
// result, and rolls every migration back in reverse order.
func TestShippedMigrationsRunInOrder(t *testing.T) {
	for _, schema := range []string{"authkit", "Shipped_Identity"} {
		t.Run(schema, func(t *testing.T) {
			ctx := context.Background()
			db := openTestDB(t)
			quoted := `"` + schema + `"`
			_, _ = db.Exec(`DROP SCHEMA IF EXISTS ` + quoted + ` CASCADE`)
			// With no authkit schema present, a statement the rename missed fails
			// or recreates authkit, which the custom run checks for below.
			applyMigration(t, db, "000001_identity_schema.down.sql")
			t.Cleanup(func() {
				_, _ = db.Exec(`DROP SCHEMA IF EXISTS ` + quoted + ` CASCADE`)
				_ = db.Close()
			})

			fsys, err := authkit.Migrations(schema)
			if err != nil {
				t.Fatal(err)
			}
			ups, err := fs.Glob(fsys, "*.up.sql")
			if err != nil || len(ups) == 0 {
				t.Fatalf("up migrations: %v %v", ups, err)
			}
			downs, err := fs.Glob(fsys, "*.down.sql")
			if err != nil || len(downs) != len(ups) {
				t.Fatalf("down migrations: %v %v", downs, err)
			}
			run := func(name string) {
				t.Helper()
				data, err := fs.ReadFile(fsys, name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(string(data)); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
			}

			for _, name := range ups { // fs.Glob sorts, and the names sort by version
				run(name)
			}
			assertTablesExistInSchema(t, db, schema,
				"tenants", "users", "memberships", "invitations", "api_keys", "provider_keys",
				"refresh_tokens", "verification_codes", "user_status_changes", "sessions", "external_identities")
			if schema != "authkit" && schemaExists(t, db, "authkit") {
				t.Fatal("migrations for a custom schema created the authkit schema")
			}

			repo := repository.NewWithSchema(db, db, schema)
			userID := createTenantAndUser(t, ctx, &repo, "shipped.test")
			k := verifiedKit(t, db, authkit.SessionRequired, nil, schema)
			resp := openSession(t, k, model.OpenSessionRequest{UserID: userID, SignInMethod: "google"})
			if _, err := k.AuthService().ValidateJWT(ctx, resp.AccessToken); err != nil {
				t.Fatalf("validate a token from a migrated schema: %v", err)
			}
			if _, err := k.ExternalIdentityService().Link(ctx, model.LinkExternalIdentityRequest{UserID: userID, Provider: "google", Subject: "sub-1"}); err != nil {
				t.Fatalf("link in a migrated schema: %v", err)
			}
			if err := k.UserService().MarkEmailVerified(ctx, userID); err != nil {
				t.Fatalf("mark email verified in a migrated schema: %v", err)
			}

			for i := len(downs) - 1; i >= 0; i-- {
				run(downs[i])
			}
			if schemaExists(t, db, schema) {
				t.Fatalf("schema %s still exists after every down migration", schema)
			}
		})
	}
}

func schemaExists(t *testing.T, db *sql.DB, schema string) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = $1)`, schema).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}
