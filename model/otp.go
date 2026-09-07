// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "time"

// GenerateResponse contains the generated OTP code and expiration timestamp
type GenerateResponse struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

// OTPGenerateRequest is the input to OTPService.Generate. Codes are keyed by
// (Email, Purpose) globally — email is a global identity now, so an OTP for
// signup/reset is identity-level, not tenant-scoped. The email is normalized by the
// service.
type OTPGenerateRequest struct {
	Email              string        // Recipient email (normalized by the service)
	Purpose            string        // Caller-defined purpose (e.g. "signup", "reset-password")
	ExpirationDuration time.Duration // How long the issued code remains valid. Required and must be > 0; a zero/omitted value is rejected (it would yield an already-expired code).
}

// OTPValidateRequest is the input to OTPService.Validate. The fields must match the
// (Email, Purpose) used at generation; the email is normalized by the service.
type OTPValidateRequest struct {
	Email   string // Recipient email (normalized by the service)
	Code    string // The code supplied by the user
	Purpose string // Must match the purpose used at generation
}
