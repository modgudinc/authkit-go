// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
	"github.com/modgudinc/authkit-go/ratelimit"
)

// pgStringDataRightTruncation is the PostgreSQL SQLSTATE for a value that is too
// long for its column (22001). It is a caller-input problem, not an internal fault.
const pgStringDataRightTruncation = "22001"

// publicSentinels are the errors callers are expected to branch on with
// errors.Is. sanitizeError lets these pass through unchanged.
var publicSentinels = []error{
	model.ErrSessionDisabled,
	model.ErrSessionRequired,
	model.ErrSessionRevoked,
	model.ErrNotFound,
	model.ErrInvalidCredentials,
	model.ErrAccountDisabled,
	model.ErrAccountLocked,
	model.ErrInvalidToken,
	model.ErrTokenRevoked,
	model.ErrNoActiveMembership,
	model.ErrLastRoleHolder,
	model.ErrInvalidRefreshToken,
	model.ErrRefreshTokenReuse,
	model.ErrInvalidOTP,
	model.ErrOTPLockedOut,
	model.ErrOTPRateLimited,
	model.ErrOTPSecretMissing,
	model.ErrInvalidAPIKey,
	model.ErrIncorrectPassword,
	model.ErrInvitationInvalid,
	model.ErrUserExists,
	model.ErrPasswordTooWeak,
	model.ErrSecretEncryptionKeyMissing,
	model.ErrRateLimited,
	model.ErrInvalidInput,
	model.ErrValueTooLong,
}

// sanitizeError generalizes a repository error before it crosses the public API
// boundary. A known sentinel passes through so callers can still errors.Is it;
// any other error (a genuine DB/driver fault) is logged in full server-side and
// replaced with model.ErrInternal so driver/schema/constraint details are not
// exposed to callers that may render err.Error() to end users.
func sanitizeError(ctx context.Context, log logger.Logger, op string, err error) error {
	if err == nil {
		return nil
	}
	for _, sentinel := range publicSentinels {
		if errors.Is(err, sentinel) {
			return err
		}
	}
	// A value-too-long DB error (SQLSTATE 22001) is a caller-input problem, not an
	// internal fault — map it to the matchable ErrValueTooLong sentinel so callers
	// can return a 400 instead of an opaque ErrInternal. This covers every VARCHAR
	// column uniformly (tenant_id, name, secret key, email, display_name, ...).
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgStringDataRightTruncation {
		if log != nil {
			log.Warn(ctx, "input value too long", "op", op, "error", err.Error())
		}
		return fmt.Errorf("%s: %w", op, model.ErrValueTooLong)
	}
	if log != nil {
		log.Error(ctx, "internal error", "op", op, "error", err.Error())
	}
	return fmt.Errorf("%s: %w", op, model.ErrInternal)
}

// ensureLogger returns l, or a no-op logger when l is nil. Service constructors run
// their logger argument through it so every service holds a non-nil logger and can
// log unconditionally — call sites do not need an `if s.logger != nil` guard.
func ensureLogger(l logger.Logger) logger.Logger {
	if l == nil {
		return logger.NopLogger{}
	}
	return l
}

// incMetric increments a counter on m unless m is nil. Services hold an optional
// metrics.Metrics that may be nil (e.g. when constructed via a struct literal in a
// test), so emit sites call this helper rather than m.IncCounter directly to stay
// nil-safe without a per-call-site guard.
func incMetric(m metrics.Metrics, name string, labels ...string) {
	if m != nil {
		m.IncCounter(name, labels...)
	}
}

// checkRateLimit consults rl (if non-nil) for key and returns model.ErrRateLimited
// when the operation should be rejected. A nil limiter means no limiting. A limiter
// error is logged and treated as "allow" (fail open) so a limiter-backend outage
// degrades to no-limiting rather than a hard auth outage; an implementation that
// wants fail-closed should return (false, nil) from Allow on its own errors.
func checkRateLimit(ctx context.Context, rl ratelimit.RateLimiter, m metrics.Metrics, log logger.Logger, key string) error {
	if rl == nil {
		return nil
	}
	allowed, err := rl.Allow(ctx, key)
	if err != nil {
		if log != nil {
			log.Warn(ctx, "rate limiter error; allowing (fail open)", "key", key, "error", err.Error())
		}
		incMetric(m, metrics.CounterRateLimiterError)
		return nil
	}
	if !allowed {
		incMetric(m, metrics.CounterRateLimited, "key", key)
		return model.ErrRateLimited
	}
	return nil
}
