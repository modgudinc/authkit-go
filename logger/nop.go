// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package logger

import "context"

// NopLogger is a Logger implementation that discards all log records. Use it as
// a safe non-nil default when you want to inject a logger but not emit anything:
//
//	cfg.Logger = logger.NopLogger{}
//
// The library also accepts a nil Logger (logging is skipped), so NopLogger is
// only a convenience for callers that prefer a non-nil value.
type NopLogger struct{}

// Debug implements Logger and discards the record.
func (NopLogger) Debug(ctx context.Context, msg string, fields ...interface{}) {}

// Info implements Logger and discards the record.
func (NopLogger) Info(ctx context.Context, msg string, fields ...interface{}) {}

// Error implements Logger and discards the record.
func (NopLogger) Error(ctx context.Context, msg string, fields ...interface{}) {}

// Warn implements Logger and discards the record.
func (NopLogger) Warn(ctx context.Context, msg string, fields ...interface{}) {}
