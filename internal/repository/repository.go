// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/lib/pq"
)

const DefaultIdentitySchema = "authkit"

// schemaPlaceholder is the token embedded in query strings where the configured
// identity schema should be substituted. q() replaces it (with the quoted schema
// name) at call time. "{{...}}" is not valid SQL, so it can never collide with a
// real identifier, comment, or string literal — unlike a bare "authkit." prefix,
// which would silently rewrite any such substring that happened to appear.
const schemaPlaceholder = "{{schema}}"

type Repository struct {
	rw           *sql.DB
	ro           *sql.DB
	schemaPrefix string
}

func New(rw *sql.DB, ro *sql.DB) Repository {
	return NewWithSchema(rw, ro, DefaultIdentitySchema)
}

func NewWithSchema(rw *sql.DB, ro *sql.DB, schema string) Repository {
	if schema == "" {
		schema = DefaultIdentitySchema
	}

	if !IsIdentifier(schema) {
		panic(fmt.Sprintf("invalid identity schema name: %q", schema))
	}

	return Repository{
		rw:           rw,
		ro:           ro,
		schemaPrefix: pq.QuoteIdentifier(schema) + ".",
	}
}

func (r *Repository) q(query string) string {
	return strings.ReplaceAll(query, schemaPlaceholder+".", r.schemaPrefix)
}

func IsIdentifier(value string) bool {
	if value == "" {
		return false
	}

	for i, ch := range value {
		if ch == '_' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (i > 0 && ch >= '0' && ch <= '9') {
			continue
		}
		return false
	}

	return true
}
