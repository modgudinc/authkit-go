// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package ratelimit defines the optional throttle seam for authkit-go.
//
// The library deliberately does not implement rate limiting itself — the
// per-account failed-login lockout does not stop password spraying, distributed
// guessing, refresh abuse, or OTP-email fan-out (see SECURITY.md, "Caller-Owned
// Controls"). A RateLimiter is where an application plugs that in so the rate-limited
// path is the default rather than something bolted on at the HTTP layer.
//
// It mirrors the logger and metrics seams: inject an implementation via
// Config.RateLimiter, or leave it nil for no limiting.
package ratelimit

import "context"

// RateLimiter decides whether a rate-sensitive operation may proceed. The library
// calls Allow before AuthService.Login, AuthService.RefreshToken,
// OTPService.Generate, and TwoFactorService.CompleteSecondFactor.
//
// key is a stable string the library derives from the operation and the most
// security-relevant identifier available, so an implementation can bucket on it
// directly (most limiters hash the key). The formats are:
//
//   - "login:<tenantID>:<ipAddress>"      — or "login:<tenantID>:email:<email>" when no IP is supplied
//   - "refresh:<ipAddress>"               — or "refresh:" when no IP is supplied
//   - "otp:<tenantID>:<email>:<purpose>"
//   - "second_factor:<userID>"            — a code finishing a password login
//
// Return (true, nil) to allow and (false, nil) to reject — a rejection surfaces to
// the caller as authkit.ErrRateLimited. A non-nil error is treated as a limiter
// failure and the library FAILS OPEN (the operation proceeds and the error is
// logged), so a limiter backend outage degrades to "no limiting" rather than a hard
// authentication outage; an implementation that prefers fail-closed should catch its
// own backend errors and return (false, nil) instead.
//
// Implementations must be safe for concurrent use and fast — Allow is on the hot
// authentication path.
type RateLimiter interface {
	Allow(ctx context.Context, key string) (bool, error)
}
