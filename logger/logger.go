// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package logger

// Logger defines a minimal logging interface that can be implemented by
// any logging library (zap, logrus, standard log, etc.)
//
// Consumers of authkit-go can inject their own logger implementation
// to receive structured logs from the library.
//
// Example implementation with zap:
//
//	type ZapLogger struct {
//	    logger *zap.Logger
//	}
//
//	func (z *ZapLogger) Debug(msg string, fields ...interface{}) {
//	    z.logger.Sugar().Debugw(msg, fields...)
//	}
//
//	func (z *ZapLogger) Info(msg string, fields ...interface{}) {
//	    z.logger.Sugar().Infow(msg, fields...)
//	}
//
//	func (z *ZapLogger) Error(msg string, fields ...interface{}) {
//	    z.logger.Sugar().Errorw(msg, fields...)
//	}
//
//	func (z *ZapLogger) Warn(msg string, fields ...interface{}) {
//	    z.logger.Sugar().Warnw(msg, fields...)
//	}
type Logger interface {
	// Debug logs verbose diagnostic messages with optional key-value fields.
	// Use it for high-volume or lower-sensitivity detail that should be
	// suppressible in production.
	Debug(msg string, fields ...interface{})

	// Info logs informational messages with optional key-value fields
	Info(msg string, fields ...interface{})

	// Error logs error messages with optional key-value fields
	Error(msg string, fields ...interface{})

	// Warn logs warning messages with optional key-value fields
	Warn(msg string, fields ...interface{})
}
