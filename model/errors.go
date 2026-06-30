// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "errors"

// Sentinel errors returned by the library so callers can branch on outcome with
// errors.Is instead of matching on error strings. They are defined in the model
// (leaf) package so every layer can return them without an import cycle; the root
// authkit package re-exports the common ones for convenience.
//
// Errors that add context wrap one of these with %w, so errors.Is keeps working.
var (
	// ErrNotFound is returned (wrapped) when a requested record does not exist.
	ErrNotFound = errors.New("authkit: not found")

	// ErrInvalidCredentials is returned by Login when authentication fails. It is
	// deliberately generic — it covers unknown email, wrong password, disabled,
	// and locked accounts — so the unauthenticated caller cannot distinguish them
	// (account enumeration / state disclosure). The specific reason is logged
	// server-side only.
	ErrInvalidCredentials = errors.New("authkit: invalid credentials")

	// ErrAccountDisabled and ErrAccountLocked describe account state. They are
	// returned by authenticated/admin paths (e.g. ValidateJWT) but NOT by Login,
	// which collapses them into ErrInvalidCredentials.
	ErrAccountDisabled = errors.New("authkit: account is disabled")
	ErrAccountLocked   = errors.New("authkit: account is locked")

	// ErrInvalidToken is returned when an access token is malformed, expired, or
	// fails signature verification.
	ErrInvalidToken = errors.New("authkit: invalid token")

	// ErrTokenRevoked is returned when an access token is well-formed but has been
	// revoked (token_version mismatch).
	ErrTokenRevoked = errors.New("authkit: token has been revoked")

	// ErrInvalidRefreshToken is returned when a refresh token is unknown, expired,
	// or already consumed.
	ErrInvalidRefreshToken = errors.New("authkit: invalid refresh token")

	// ErrRefreshTokenReuse is returned when an already-consumed refresh token is
	// presented again, which indicates possible theft. When this happens the
	// entire token family for that user/session is revoked.
	ErrRefreshTokenReuse = errors.New("authkit: refresh token reuse detected")

	// ErrInvalidOTP is returned when an OTP is wrong, expired, or not found.
	ErrInvalidOTP = errors.New("authkit: invalid or expired OTP")

	// ErrOTPLockedOut is returned when an OTP has exceeded the allowed number of
	// failed validation attempts and has been invalidated.
	ErrOTPLockedOut = errors.New("authkit: too many invalid OTP attempts")

	// ErrOTPRateLimited is returned by OTP generation when a new code is requested
	// before the per-(email, purpose) rate-limit window has elapsed.
	ErrOTPRateLimited = errors.New("authkit: OTP rate limit exceeded")

	// ErrOTPSecretMissing is returned by OTPService.Generate/Validate when no OTP
	// HMAC secret was configured (OTPConfig.HMACSecret). OTP codes are stored as a
	// keyed HMAC, so the secret is required to use the OTP service — analogous to
	// ErrSecretEncryptionKeyMissing for SecretService. It surfaces a construction-
	// time misconfiguration as a matchable sentinel instead of an opaque error.
	ErrOTPSecretMissing = errors.New("authkit: OTP HMAC secret not configured")

	// ErrInvalidAPIKey is returned when an API key is malformed, unknown, or expired.
	ErrInvalidAPIKey = errors.New("authkit: invalid API key")

	// ErrIncorrectPassword is returned when a supplied current password does not
	// match (e.g. during ChangePassword).
	ErrIncorrectPassword = errors.New("authkit: incorrect password")

	// ErrInvitationInvalid is returned when an invitation code is unknown, expired,
	// or has no remaining uses.
	ErrInvitationInvalid = errors.New("authkit: invitation is invalid or expired")

	// ErrUserExists is returned (wrapped) when creating a global user whose email
	// already exists — i.e. a lower(email) uniqueness conflict. (Accepting an
	// invitation for an email that already has an identity is NOT an error: the
	// existing identity is reused and granted the invited membership.)
	ErrUserExists = errors.New("authkit: user already exists")

	// ErrPasswordTooWeak is returned (wrapped) when a password fails the strength
	// policy — too short, too long (bcrypt caps input at 72 bytes), or missing a
	// required character class. The specific reason is included as wrapping
	// context; callers branch on the sentinel with errors.Is.
	ErrPasswordTooWeak = errors.New("authkit: password does not meet strength requirements")

	// ErrSecretEncryptionKeyMissing is returned by SecretService operations when no
	// (or an invalid-length) secret encryption key was configured. It surfaces a
	// construction-time misconfiguration as a matchable sentinel instead of an
	// opaque internal error.
	ErrSecretEncryptionKeyMissing = errors.New("authkit: secret encryption key not configured")

	// ErrRateLimited is returned by Login, RefreshToken, and OTP generation when a
	// configured RateLimiter rejects the operation. Callers should map it to HTTP 429.
	ErrRateLimited = errors.New("authkit: rate limited")

	// ErrInvalidInput is returned (wrapped) when caller-supplied data is malformed in
	// a way that is the caller's fault rather than an internal fault — e.g. tenant
	// settings that cannot be serialized to JSON. It is a matchable input error so
	// callers can return a 400 instead of treating it as an opaque ErrInternal (500).
	ErrInvalidInput = errors.New("authkit: invalid input")

	// ErrValueTooLong is returned (wrapped) when a caller-supplied string exceeds the
	// maximum length the store allows for its column (e.g. an over-length tenant_id,
	// name, secret key, email, or display name), or when tenant settings exceed the
	// serialized-size cap. It is a matchable input error so callers can return a 400
	// rather than treating an over-length value as an opaque internal fault.
	ErrValueTooLong = errors.New("authkit: value exceeds maximum allowed length")

	// ErrInternal is returned (wrapped) when an unexpected internal/storage error
	// occurs. The underlying cause is logged server-side; callers receive this
	// generic error so driver/schema details do not leak across the API boundary.
	ErrInternal = errors.New("authkit: internal error")
)
