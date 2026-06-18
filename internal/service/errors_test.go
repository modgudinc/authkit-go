// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/modgudinc/authkit-go/model"
)

func TestSanitizeErrorMapsValueTooLong(t *testing.T) {
	// A Postgres "value too long for type character varying(N)" (SQLSTATE 22001)
	// must surface as the matchable ErrValueTooLong, not the opaque ErrInternal, so
	// callers can return a 400 for an over-length input.
	pgErr := &pgconn.PgError{Code: pgStringDataRightTruncation, Message: "value too long for type character varying(255)"}
	wrapped := fmt.Errorf("create tenant: %w", pgErr) // mirror the repo's error wrapping

	got := sanitizeError(nil, "create tenant", wrapped)
	if !errors.Is(got, model.ErrValueTooLong) {
		t.Fatalf("expected ErrValueTooLong, got %v", got)
	}
	if errors.Is(got, model.ErrInternal) {
		t.Fatal("a value-too-long error must not collapse to ErrInternal")
	}
}

func TestSanitizeErrorPassesThroughSentinelAndHidesOtherFaults(t *testing.T) {
	// A known sentinel passes through unchanged.
	if got := sanitizeError(nil, "op", fmt.Errorf("wrap: %w", model.ErrNotFound)); !errors.Is(got, model.ErrNotFound) {
		t.Fatalf("expected ErrNotFound to pass through, got %v", got)
	}
	// An unknown fault is replaced with the generic ErrInternal.
	if got := sanitizeError(nil, "op", errors.New("driver exploded")); !errors.Is(got, model.ErrInternal) {
		t.Fatalf("expected ErrInternal for an unknown fault, got %v", got)
	}
}
