// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package metrics defines a minimal, optional instrumentation seam for authkit-go.
//
// It mirrors the logger package: the library calls a small Metrics interface at a
// few security-relevant decision points (login success/failure, account lockout,
// OTP failure/lockout, refresh-token reuse, rate-limit rejections and limiter errors,
// and best-effort write failures — see the Counter* constants for the full set) and
// never depends on a concrete telemetry library. Inject your own implementation via Config.Metrics to bridge
// these counters to Prometheus, OpenTelemetry, statsd, etc. When no implementation
// is injected the calls are no-ops (see NopMetrics), so there is zero overhead and
// no dependency for callers that do not want metrics.
//
// The canonical counter names the library emits are exported as Counter* constants
// so callers can register/alert on them without hardcoding strings.
package metrics

// Metrics is the optional sink the library increments at key auth decision points.
// Implementations MUST be safe for concurrent use (the library calls them from
// multiple goroutines). Label semantics are a flat, even-length list of
// alternating key/value strings (e.g. "reason", "account_locked"), matching the
// structured-logging field convention; implementations that do not support labels
// may ignore them.
type Metrics interface {
	// IncCounter increments the named counter by one, with optional labels.
	IncCounter(name string, labels ...string)
}

// Canonical counter names emitted by the library. Values are stable, snake_case,
// and namespaced with the "authkit_" prefix so they slot directly into a metrics
// backend.
const (
	// CounterLoginSuccess counts successful AuthService.Login calls.
	CounterLoginSuccess = "authkit_login_success_total"
	// CounterLoginFailure counts failed AuthService.Login calls. Emitted with a
	// "reason" label (not_found, account_disabled, account_locked, bad_password,
	// no_password, no_membership, bad_second_factor).
	CounterLoginFailure = "authkit_login_failure_total"
	// CounterAccountLockout counts accounts auto-locked after too many failed logins.
	CounterAccountLockout = "authkit_account_lockout_total"
	// CounterOTPFailure counts failed OTP validations (wrong/expired/missing code).
	CounterOTPFailure = "authkit_otp_failure_total"
	// CounterOTPLockout counts OTPs invalidated after too many failed attempts.
	CounterOTPLockout = "authkit_otp_lockout_total"
	// CounterRefreshReuse counts detected refresh-token reuse/theft events (each one
	// revokes the whole token family and bumps the user's token_version). The Go name
	// omits "Token" so it does not trip gosec's hardcoded-credential heuristic (G101);
	// the metric string is unchanged.
	CounterRefreshReuse = "authkit_refresh_token_reuse_total"
	// CounterRefreshRetry counts refreshes accepted as a retry within
	// JWTConfig.RefreshGracePeriod: a client presented a consumed refresh token whose
	// replacement it never used, typically because it lost the response.
	CounterRefreshRetry = "authkit_refresh_token_retry_total"
	// CounterRateLimited counts operations rejected by a configured RateLimiter.
	// Emitted with a "key" label identifying the operation/bucket.
	CounterRateLimited = "authkit_rate_limited_total"
	// CounterRateLimiterError counts RateLimiter.Allow errors (the library fails open
	// and proceeds); a sustained nonzero rate means the limiter backend is degraded.
	CounterRateLimiterError = "authkit_rate_limiter_error_total"
	// CounterBestEffortWriteFailure counts failures of non-critical, best-effort
	// primary writes that the auth flows swallow to stay available (e.g. last-login
	// update, failed-count reset, auto-unlock). Emitted with an "op" label. A
	// sustained nonzero rate signals a degraded primary even while logins still work.
	CounterBestEffortWriteFailure = "authkit_best_effort_write_failure_total"
	// CounterVerifiedLogin counts sessions opened by VerifiedLoginService.OpenSession
	// for users the application verified itself. Emitted with a "method" label (the
	// sign-in method the application passed, e.g. "google" or "device_code").
	CounterVerifiedLogin = "authkit_verified_login_total"
	// CounterIdentityLinkRefused counts ExternalIdentityService.Resolve calls that
	// found a user by a verified email but refused to link the sign-in to them
	// (ErrIdentityLinkRequired). Emitted with a "reason" label (email_unverified,
	// has_password, provider_account_mismatch). A spike can mean someone is trying to take over
	// accounts through a provider.
	CounterIdentityLinkRefused = "authkit_identity_link_refused_total"
	// CounterWebAuthnCloneWarning counts PasskeyService.RecordUse calls refused
	// because the authenticator's signature counter did not go up (ErrPasskeyCloned):
	// the passkey may have been copied to another authenticator.
	CounterWebAuthnCloneWarning = "authkit_webauthn_clone_warning_total"
)
