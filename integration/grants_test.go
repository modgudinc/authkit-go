//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"database/sql"
	"io/fs"
	"sort"
	"strings"
	"testing"

	authkit "github.com/modgudinc/authkit-go"
)

// Every table the migrations create must be reachable by the optional authkit_rw
// and authkit_ro roles once every migration has run: 000001 grants on the tables
// that exist when it runs, so each later migration that adds a table has to grant
// on it (000002 did not, which 000010 repairs). The test creates the roles, applies
// every up migration in order, and checks each table's privileges, so a new
// migration without its grant block fails here.
func schemaTables(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'authkit' AND table_type = 'BASE TABLE' ORDER BY table_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return tables
}

func TestMigrationsGrantEveryTableToRoles(t *testing.T) {
	db := openTestDB(t)
	const createRoles = `DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authkit_rw') THEN CREATE ROLE authkit_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authkit_ro') THEN CREATE ROLE authkit_ro NOLOGIN; END IF;
END;
$$;`
	applyMigration(t, db, "000001_identity_schema.down.sql")
	if _, err := db.Exec(createRoles); err != nil {
		t.Skipf("cannot create the roles (needs CREATEROLE): %v", err)
	}
	defer func() {
		// Dropping the schema drops the grants, which the roles depend on.
		applyMigration(t, db, "000001_identity_schema.down.sql")
		if _, err := db.Exec("DROP ROLE IF EXISTS authkit_rw; DROP ROLE IF EXISTS authkit_ro"); err != nil {
			t.Errorf("drop roles: %v", err)
		}
		_ = db.Close()
	}()

	fsys, err := authkit.Migrations("")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		t.Fatal(err)
	}
	var ups []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".up.sql") {
			ups = append(ups, entry.Name())
		}
	}
	sort.Strings(ups)
	if len(ups) < 10 {
		t.Fatalf("expected at least ten up migrations, found %d", len(ups))
	}
	for _, name := range ups {
		applyMigration(t, db, name)
	}

	tables := schemaTables(t, db)
	if len(tables) < 15 {
		t.Fatalf("expected the whole schema, found tables %v", tables)
	}

	hasPrivilege := func(role, table, privilege string) bool {
		var ok bool
		if err := db.QueryRow(`SELECT has_table_privilege($1, $2, $3)`, role, "authkit."+table, privilege).Scan(&ok); err != nil {
			t.Fatalf("has_table_privilege(%s, %s, %s): %v", role, table, privilege, err)
		}
		return ok
	}
	for _, table := range tables {
		for _, privilege := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
			if !hasPrivilege("authkit_rw", table, privilege) {
				t.Errorf("authkit_rw lacks %s on %s", privilege, table)
			}
		}
		if !hasPrivilege("authkit_ro", table, "SELECT") {
			t.Errorf("authkit_ro lacks SELECT on %s", table)
		}
		for _, privilege := range []string{"INSERT", "UPDATE", "DELETE"} {
			if hasPrivilege("authkit_ro", table, privilege) {
				t.Errorf("authkit_ro has %s on %s", privilege, table)
			}
		}
	}

	// 000010's down takes the sessions grants away again, and nothing else.
	applyMigration(t, db, "000010_sessions_grants.down.sql")
	if hasPrivilege("authkit_rw", "sessions", "SELECT") || hasPrivilege("authkit_ro", "sessions", "SELECT") {
		t.Error("000010 down left the sessions grants in place")
	}
	if !hasPrivilege("authkit_rw", "users", "SELECT") {
		t.Error("000010 down touched a table other than sessions")
	}
}
