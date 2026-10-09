// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"bytes"
	"embed"
	"errors"
	"io"
	"io/fs"
	"regexp"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modgudinc/authkit-go/internal/repository"
)

// migrationFiles is the SQL in migrations/, shipped inside the module.
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

var (
	// qualifiedName matches the schema in a schema-qualified name: authkit.users.
	qualifiedName = regexp.MustCompile(`\bauthkit\.`)
	// schemaClause matches the schema where a statement names it alone:
	// CREATE SCHEMA IF NOT EXISTS authkit, DROP SCHEMA IF EXISTS authkit,
	// ON SCHEMA authkit, IN SCHEMA authkit.
	schemaClause = regexp.MustCompile(`\bSCHEMA (IF (?:NOT )?EXISTS )?authkit\b`)
)

// Migrations returns authkit's SQL migrations as a flat file system of numbered
// pairs, 000001_identity_schema.up.sql and 000001_identity_schema.down.sql onwards:
// the layout golang-migrate reads (source/iofs) and other tools that run
// NNNNNN_name.up.sql files in order. Apply every up migration in order; the ones
// only some features need just add tables and columns that stay unused otherwise.
// See docs/migrations.md.
//
// schema is the DatabaseConnection.IdentitySchema the application configures. ""
// and "authkit" return the files exactly as shipped. Any other valid identifier
// returns the same SQL with that schema, quoted, wherever it names the authkit
// schema; the optional authkit_rw and authkit_ro roles it grants to keep their
// names.
//
// A migration that has shipped in a release never changes; schema changes arrive
// as new numbered migrations.
func Migrations(schema string) (fs.FS, error) {
	if schema == "" {
		schema = repository.DefaultIdentitySchema
	}
	if !repository.IsIdentifier(schema) {
		return nil, errors.New("identity schema must be a valid PostgreSQL identifier")
	}
	shipped, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return nil, err
	}
	if schema == repository.DefaultIdentitySchema {
		return shipped, nil
	}

	entries, err := fs.ReadDir(shipped, ".")
	if err != nil {
		return nil, err
	}
	quoted := pgx.Identifier{schema}.Sanitize()
	rendered := &migrationFS{files: make(map[string][]byte, len(entries))}
	for _, entry := range entries {
		data, err := fs.ReadFile(shipped, entry.Name())
		if err != nil {
			return nil, err
		}
		data = qualifiedName.ReplaceAllLiteral(data, []byte(quoted+"."))
		data = schemaClause.ReplaceAll(data, []byte("SCHEMA ${1}"+quoted))
		rendered.names = append(rendered.names, entry.Name())
		rendered.files[entry.Name()] = data
	}
	sort.Strings(rendered.names)
	return rendered, nil
}

// migrationFS is a flat, read-only, in-memory file system of migrations rendered
// for a custom schema.
type migrationFS struct {
	names []string // sorted
	files map[string][]byte
}

func (m *migrationFS) Open(name string) (fs.File, error) {
	if name == "." {
		return &migrationDir{fsys: m}, nil
	}
	data, err := m.file("open", name)
	if err != nil {
		return nil, err
	}
	return &migrationFile{info: migrationInfo{name: name, size: int64(len(data))}, Reader: bytes.NewReader(data)}, nil
}

func (m *migrationFS) ReadFile(name string) ([]byte, error) {
	data, err := m.file("readfile", name)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(data), nil
}

func (m *migrationFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name != "." {
		if !fs.ValidPath(name) {
			return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
		}
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	return m.entries(m.names), nil
}

func (m *migrationFS) file(op, name string) ([]byte, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}
	data, ok := m.files[name]
	if !ok {
		return nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
	}
	return data, nil
}

func (m *migrationFS) entries(names []string) []fs.DirEntry {
	entries := make([]fs.DirEntry, len(names))
	for i, name := range names {
		entries[i] = fs.FileInfoToDirEntry(migrationInfo{name: name, size: int64(len(m.files[name]))})
	}
	return entries
}

type migrationFile struct {
	info migrationInfo
	*bytes.Reader
}

func (f *migrationFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *migrationFile) Close() error               { return nil }

// migrationDir is the file system's root directory, opened.
type migrationDir struct {
	fsys *migrationFS
	read int
}

func (d *migrationDir) Stat() (fs.FileInfo, error) { return migrationInfo{name: ".", dir: true}, nil }
func (d *migrationDir) Close() error               { return nil }

func (d *migrationDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: ".", Err: errors.New("is a directory")}
}

func (d *migrationDir) ReadDir(n int) ([]fs.DirEntry, error) {
	rest := d.fsys.names[d.read:]
	if n > 0 {
		if len(rest) == 0 {
			return nil, io.EOF
		}
		rest = rest[:min(n, len(rest))]
	}
	d.read += len(rest)
	return d.fsys.entries(rest), nil
}

type migrationInfo struct {
	name string
	size int64
	dir  bool
}

func (i migrationInfo) Name() string       { return i.name }
func (i migrationInfo) Size() int64        { return i.size }
func (i migrationInfo) ModTime() time.Time { return time.Time{} }
func (i migrationInfo) IsDir() bool        { return i.dir }
func (i migrationInfo) Sys() any           { return nil }

func (i migrationInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o555
	}
	return 0o444
}
