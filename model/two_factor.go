// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "time"

// SecondFactorRequiredError is the error a password login returns when the user
// has two-factor on. It unwraps to ErrSecondFactorRequired. Send Challenge to the
// client, ask for a code, and finish with TwoFactorService.CompleteSecondFactor
// before ExpiresAt. Challenge is a secret: it lets whoever holds it finish this
// login with a code.
type SecondFactorRequiredError struct {
	Challenge string
	ExpiresAt time.Time
}

func (e *SecondFactorRequiredError) Error() string { return ErrSecondFactorRequired.Error() }

// Unwrap lets errors.Is(err, ErrSecondFactorRequired) match.
func (e *SecondFactorRequiredError) Unwrap() error { return ErrSecondFactorRequired }

// CompleteSecondFactorRequest finishes a password login that returned
// ErrSecondFactorRequired.
type CompleteSecondFactorRequest struct {
	// Challenge is SecondFactorRequiredError.Challenge.
	Challenge string `json:"challenge"`
	// Code is the 6-digit code from the person's authenticator app, or one of their
	// recovery codes.
	Code string `json:"code"`
}

// TOTPEnrollment is a new authenticator-app secret waiting for its first code
// (TwoFactorService.EnrollTOTP). Show URI as a QR code and Secret for typing in.
// Neither is stored in the clear, and neither can be read back later.
type TOTPEnrollment struct {
	// Secret is the shared secret in base32, without padding.
	Secret string `json:"secret"`
	// URI is the otpauth:// URI authenticator apps read from a QR code.
	URI string `json:"uri"`
}

// TwoFactorStatus describes a user's two-factor setup (TwoFactorService.Status).
type TwoFactorStatus struct {
	// Enabled is true once the person has confirmed an authenticator app; their
	// password logins then need a second factor.
	Enabled   bool       `json:"enabled"`
	EnabledAt *time.Time `json:"enabled_at,omitempty"`
	// RecoveryCodesLeft counts the unused recovery codes.
	RecoveryCodesLeft int `json:"recovery_codes_left"`
}
