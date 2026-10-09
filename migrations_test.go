// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

// shippedMigrations pins the SHA-256 of every migration file. A migration that has
// shipped in a release never changes: databases have already run it, and tools such
// as golang-migrate never run it again, so an edit would reach new databases only
// and the two would drift apart. Change the schema with a new numbered migration
// instead (CONTRIBUTING.md). A migration added since the last release may still
// change, together with its line here.
var shippedMigrations = map[string]string{ //nolint:gosec // G101 false positive: SHA-256 checksums of migration files, not credentials
	// 000001 and 000002 as released in v0.20.2.
	"000001_identity_schema.down.sql":           "104a53b2ff959c2eed2b3778dd2488f92263b20118a43ae2ccc7cf7539e323b2",
	"000001_identity_schema.up.sql":             "fcb081b2c701d934aab537df56c0aff9bb757614758e821ee72dce293412c7d0",
	"000002_installation_sessions.down.sql":     "88455155206e643c5f54bf22f946cbf0e19707446f382b78a40bb2dd13b3c6a3",
	"000002_installation_sessions.up.sql":       "0fa30a714a55006c94f8beb9e57d532cabdc587d11e8575e638541cb368d7704",
	"000003_session_sign_in.down.sql":           "9fb5cec500cde452eff0046b1f5fca0407ded0987248f77c8ca4d995cc0b4b80",
	"000003_session_sign_in.up.sql":             "cd0cdf95a1ad4e112c52baf6e328747140267c9a5546848df8cc4b78851cbc73",
	"000004_external_identities.down.sql":       "3e46f975a1f48235703fc2381e3cf22773fe4d2ade53cc75d98dbeeebc37e867",
	"000004_external_identities.up.sql":         "7ad54ed53619c9c5b9d8490f08cb4283b7a82b8e45a35f14a058ee4cb45e0b99",
	"000005_email_verification.down.sql":        "1065388079327fd43f20d80b06c313426eea20d9ad03b55698edf2c640acda21",
	"000005_email_verification.up.sql":          "137f8f6c403fdfa79b12a5d9782205d5de3600f7846d60ce5d1aa70062dc21cd",
	"000006_refresh_token_replacement.down.sql": "a89bad16f359dd4590b5ead64da4e7a48cf621c1f66bfee0003c089ddae149e7",
	"000006_refresh_token_replacement.up.sql":   "627673dbdea6608dfbf93a6acfcab6ad1558805222acee11d0afd63138066983",
}

func shippedNames(t *testing.T) []string {
	t.Helper()
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Name()
	}
	return names
}

func TestMigrationsAreFrozen(t *testing.T) {
	names := shippedNames(t)
	for _, name := range names {
		data, err := fs.ReadFile(migrationFiles, "migrations/"+name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		want, ok := shippedMigrations[name]
		switch {
		case !ok:
			t.Errorf("%s is not pinned: add its SHA-256 (%x) to shippedMigrations", name, sum)
		case hex.EncodeToString(sum[:]) != want:
			t.Errorf("%s changed. A released migration never changes: add a new numbered migration instead (CONTRIBUTING.md)", name)
		}
	}
	shipped := map[string]bool{}
	for _, name := range names {
		shipped[name] = true
	}
	for name := range shippedMigrations {
		if !shipped[name] {
			t.Errorf("%s is pinned but no longer ships: a released migration is never removed or renamed", name)
		}
	}
}

func TestMigrationsArePairedAndNumbered(t *testing.T) {
	pattern := regexp.MustCompile(`^(\d{6})_([a-z0-9_]+)\.(up|down)\.sql$`)
	titles := map[int]string{}
	directions := map[int][]string{}
	for _, name := range shippedNames(t) {
		m := pattern.FindStringSubmatch(name)
		if m == nil {
			t.Fatalf("%s does not match NNNNNN_name.up.sql or NNNNNN_name.down.sql", name)
		}
		version, _ := strconv.Atoi(m[1])
		if title, seen := titles[version]; seen && title != m[2] {
			t.Fatalf("version %d has two names: %s and %s", version, title, m[2])
		}
		titles[version] = m[2]
		directions[version] = append(directions[version], m[3])
	}
	for version := 1; version <= len(titles); version++ {
		if got := strings.Join(directions[version], ","); got != "down,up" {
			t.Fatalf("version %d has %q, want one down and one up migration (versions run 1 to %d with no gaps)", version, got, len(titles))
		}
	}
}

func TestMigrationsDefaultSchemaIsShippedSQL(t *testing.T) {
	names := shippedNames(t)
	for _, schema := range []string{"", "authkit"} {
		fsys, err := Migrations(schema)
		if err != nil {
			t.Fatal(err)
		}
		if err := fstest.TestFS(fsys, names...); err != nil {
			t.Fatalf("Migrations(%q): %v", schema, err)
		}
		for _, name := range names {
			got, err := fs.ReadFile(fsys, name)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := fs.ReadFile(migrationFiles, "migrations/"+name)
			if !bytes.Equal(got, want) {
				t.Fatalf("Migrations(%q) changed %s", schema, name)
			}
		}
	}
}

func TestMigrationsCustomSchema(t *testing.T) {
	names := shippedNames(t)
	fsys, err := Migrations("Tenant_Identity")
	if err != nil {
		t.Fatal(err)
	}
	if err := fstest.TestFS(fsys, names...); err != nil {
		t.Fatal(err)
	}

	for _, name := range names {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			t.Fatal(err)
		}
		// Outside comments, "authkit" may only remain in the role names.
		for i, sqlLine := range strings.Split(string(data), "\n") {
			code, _, _ := strings.Cut(sqlLine, "--")
			if bareAuthkit.MatchString(code) {
				t.Errorf("%s:%d still names the authkit schema: %q", name, i+1, sqlLine)
			}
		}
		shipped, _ := fs.ReadFile(migrationFiles, "migrations/"+name)
		if bytes.Count(shipped, []byte("authkit_rw")) != bytes.Count(data, []byte("authkit_rw")) ||
			bytes.Count(shipped, []byte("authkit_ro")) != bytes.Count(data, []byte("authkit_ro")) {
			t.Errorf("%s renamed the authkit_rw or authkit_ro role", name)
		}
	}

	for name, want := range map[string][]string{
		"000001_identity_schema.up.sql": {
			`CREATE SCHEMA IF NOT EXISTS "Tenant_Identity";`,
			`CREATE TABLE IF NOT EXISTS "Tenant_Identity".users (`,
			`EXECUTE FUNCTION "Tenant_Identity".update_updated_at();`,
			`GRANT USAGE ON SCHEMA "Tenant_Identity" TO authkit_rw;`,
			`GRANT SELECT ON ALL TABLES IN SCHEMA "Tenant_Identity" TO authkit_ro;`,
		},
		"000001_identity_schema.down.sql": {`DROP SCHEMA IF EXISTS "Tenant_Identity" CASCADE;`},
		"000004_external_identities.up.sql": {
			`REFERENCES "Tenant_Identity".users(id)`,
			`GRANT SELECT ON "Tenant_Identity".external_identities TO authkit_ro;`,
		},
		"000005_email_verification.up.sql": {`ALTER TABLE "Tenant_Identity".users ADD COLUMN IF NOT EXISTS email_verified_at`},
	} {
		data, _ := fs.ReadFile(fsys, name)
		for _, s := range want {
			if !bytes.Contains(data, []byte(s)) {
				t.Errorf("%s: missing %q", name, s)
			}
		}
	}
}

// bareAuthkit matches "authkit" as a whole word: the schema, not authkit_rw.
var bareAuthkit = regexp.MustCompile(`\bauthkit\b`)

func TestMigrationsRefuseInvalidSchema(t *testing.T) {
	for _, schema := range []string{"authkit;drop", "1identity", "my identity", "my-identity", `my"identity`} {
		if _, err := Migrations(schema); err == nil {
			t.Errorf("Migrations(%q) accepted an invalid schema", schema)
		}
	}
}
