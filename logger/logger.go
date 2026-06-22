// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package logger

import "context"

// Logger defines a minimal logging interface that can be implemented by
// any logging library (zap, logrus, log/slog, etc.)
//
// Consumers of authkit-go can inject their own logger implementation
// to receive structured logs from the library.
//
// Each method takes the call's context.Context as its first argument so an
// implementation can pull request/trace/correlation IDs out of it and attach them
// to the line (as log/slog's *Context methods do). The library passes the
// operation's context where it has one; the pure-CPU services (password, JWT) do
// no I/O and have no request context, so they pass context.Background().
//
// Example implementation with log/slog:
//
//	type SlogLogger struct{ l *slog.Logger }
//
//	func (s SlogLogger) Debug(ctx context.Context, msg string, fields ...any) { s.l.DebugContext(ctx, msg, fields...) }
//	func (s SlogLogger) Info(ctx context.Context, msg string, fields ...any)  { s.l.InfoContext(ctx, msg, fields...) }
//	func (s SlogLogger) Warn(ctx context.Context, msg string, fields ...any)  { s.l.WarnContext(ctx, msg, fields...) }
//	func (s SlogLogger) Error(ctx context.Context, msg string, fields ...any) { s.l.ErrorContext(ctx, msg, fields...) }
type Logger interface {
	// Debug logs verbose diagnostic messages with optional key-value fields.
	// Use it for high-volume or lower-sensitivity detail that should be
	// suppressible in production.
	Debug(ctx context.Context, msg string, fields ...interface{})

	// Info logs informational messages with optional key-value fields
	Info(ctx context.Context, msg string, fields ...interface{})

	// Error logs error messages with optional key-value fields
	Error(ctx context.Context, msg string, fields ...interface{})

	// Warn logs warning messages with optional key-value fields
	Warn(ctx context.Context, msg string, fields ...interface{})
}
