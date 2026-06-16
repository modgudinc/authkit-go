// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "time"

// GenerateResponse contains the generated OTP code and expiration timestamp
type GenerateResponse struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

// OTPGenerateRequest is the input to OTPService.Generate. Codes are scoped to
// (TenantID, Email, Purpose); the email is normalized by the service.
type OTPGenerateRequest struct {
	TenantID           string        // Tenant the code belongs to
	Email              string        // Recipient email (normalized by the service)
	Purpose            string        // Caller-defined purpose (e.g. "signup", "reset-password")
	ExpirationDuration time.Duration // How long the issued code remains valid
}

// OTPValidateRequest is the input to OTPService.Validate. The fields must match the
// (TenantID, Email, Purpose) used at generation; the email is normalized by the
// service.
type OTPValidateRequest struct {
	TenantID string // Tenant the code belongs to
	Email    string // Recipient email (normalized by the service)
	Code     string // The code supplied by the user
	Purpose  string // Must match the purpose used at generation
}
