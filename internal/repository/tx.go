// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"sync/atomic"
)

// The caller's transaction. WithTx puts one in a context, and every query the
// repository runs for that context runs in it, so authkit's writes commit or roll back
// with the caller's own (an outbox row, say). Where the repository would begin a
// transaction of its own, it sets a savepoint in the caller's instead, so a step that
// fails and rolls back leaves the caller's transaction usable.

type callerTxKey struct{}

type callerTx struct {
	tx *sql.Tx
	// Savepoint names are unique within the transaction.
	savepoints atomic.Uint64
}

// WithTx returns a copy of ctx that makes the repository run in tx.
func WithTx(ctx context.Context, tx *sql.Tx) context.Context {
	return context.WithValue(ctx, callerTxKey{}, &callerTx{tx: tx})
}

// Detach returns a copy of ctx that runs nothing in the caller's transaction, for
// writes that must commit whatever the caller does: what a refused sign-in records,
// and work that outlives the call.
func Detach(ctx context.Context) context.Context {
	if ctx.Value(callerTxKey{}) == nil {
		return ctx
	}
	return context.WithValue(ctx, callerTxKey{}, (*callerTx)(nil))
}

func callerTxFrom(ctx context.Context) *callerTx {
	c, _ := ctx.Value(callerTxKey{}).(*callerTx)
	return c
}

// dbtx is what a query runs on: a pool, a transaction, or a savepoint in one.
type dbtx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// txn is a transaction the repository runs a write in: its own, or a savepoint in the
// caller's. Rollback after Commit does nothing, as for *sql.Tx.
type txn interface {
	dbtx
	Commit() error
	Rollback() error
}

// writer is the primary for ctx: the caller's transaction, else the read-write pool.
func (r *Repository) writer(ctx context.Context) dbtx {
	if c := callerTxFrom(ctx); c != nil {
		return c.tx
	}
	return r.rw
}

// reader is the replica for ctx. In the caller's transaction it is that transaction,
// so a read sees what the caller wrote before it.
func (r *Repository) reader(ctx context.Context) dbtx {
	if c := callerTxFrom(ctx); c != nil {
		return c.tx
	}
	return r.ro
}

// begin starts a transaction for ctx: a savepoint in the caller's, else its own.
func (r *Repository) begin(ctx context.Context) (txn, error) {
	c := callerTxFrom(ctx)
	if c == nil {
		return r.rw.BeginTx(ctx, nil)
	}
	name := fmt.Sprintf("authkit_%d", c.savepoints.Add(1))
	if _, err := c.tx.ExecContext(ctx, "SAVEPOINT "+name); err != nil {
		return nil, err
	}
	return &savepoint{Tx: c.tx, name: name}, nil
}

// savepoint is a step in the caller's transaction. Commit releases it, and Rollback
// undoes what ran since it was set, leaving the caller's transaction usable.
type savepoint struct {
	*sql.Tx
	name string
	done bool
}

func (s *savepoint) Commit() error {
	if s.done {
		return sql.ErrTxDone
	}
	s.done = true
	_, err := s.ExecContext(context.Background(), "RELEASE SAVEPOINT "+s.name)
	return err
}

func (s *savepoint) Rollback() error {
	if s.done {
		return sql.ErrTxDone
	}
	s.done = true
	if _, err := s.ExecContext(context.Background(), "ROLLBACK TO SAVEPOINT "+s.name); err != nil {
		return err
	}
	_, err := s.ExecContext(context.Background(), "RELEASE SAVEPOINT "+s.name)
	return err
}
