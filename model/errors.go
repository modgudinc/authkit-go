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

	// ErrInvalidAPIKey is returned when an API key is malformed, unknown, or expired.
	ErrInvalidAPIKey = errors.New("authkit: invalid API key")

	// ErrIncorrectPassword is returned when a supplied current password does not
	// match (e.g. during ChangePassword).
	ErrIncorrectPassword = errors.New("authkit: incorrect password")

	// ErrInvitationInvalid is returned when an invitation code is unknown, expired,
	// or has no remaining uses.
	ErrInvitationInvalid = errors.New("authkit: invitation is invalid or expired")
)
