// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "time"

// VerificationCode represents an OTP code for email verification
type VerificationCode struct {
	TenantID  string    `json:"tenant_id" db:"tenant_id"`
	Email     string    `json:"email" db:"email"`
	Code      string    `json:"-" db:"code"` // Never expose the plaintext code in JSON
	Purpose   string    `json:"purpose" db:"purpose"`
	Attempts  int       `json:"attempts" db:"attempts"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// CreateVerificationCodeRequest contains the data needed to create a new OTP code
type CreateVerificationCodeRequest struct {
	TenantID  string
	Email     string
	Code      string
	Purpose   string
	ExpiresAt time.Time
}

// GenerateResponse contains the generated OTP code and expiration timestamp
type GenerateResponse struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

// OTPConsumeResult is the outcome of attempting to consume (validate) an OTP.
type OTPConsumeResult int

const (
	// OTPConsumeInvalid means no active code matched (wrong code, wrong
	// tenant/email/purpose, expired, or not found). The code, if any, was not
	// consumed; the failed attempt may have been counted.
	OTPConsumeInvalid OTPConsumeResult = iota
	// OTPConsumeValid means the code matched and was consumed (single-use).
	OTPConsumeValid
	// OTPConsumeLockedOut means the code had reached the maximum number of failed
	// attempts and has been invalidated; the caller must request a new code.
	OTPConsumeLockedOut
)
