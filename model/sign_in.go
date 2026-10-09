// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

// OpenSessionRequest opens a session for a user the application has already
// verified itself (VerifiedLoginService.OpenSession). authkit checks no credential:
// UserID must come from the application's own verification (an OIDC ID token, a
// signed email link, an OTP, a passkey assertion, an approved device code), never
// from a request body.
type OpenSessionRequest struct {
	// UserID is the authkit user the application verified.
	UserID string
	// SignInMethod records how the person signed in, for audit: "google",
	// "github", "email_link", "otp", "passkey", "device_code" and so on. It is
	// lowercased; 1 to 64 letters, digits, '.', '_', ':' or '-'. "password" is
	// reserved for logins in which authkit checked the password.
	SignInMethod string
	// TenantID optionally selects the workspace to mint an access token for, as in
	// LoginByEmail. When empty, a token is minted only if the user has exactly one
	// active membership.
	TenantID string
	// Installation optionally binds the session to an installation the application
	// has enrolled and verified. It requires session support (SessionOptional or
	// SessionRequired).
	Installation *InstallationBinding
	SessionInfo  *SessionInfo
}

// OpenSessionResponse embeds the LoginResponse that password logins return.
// Session is the session record when session support is enabled, and nil in
// SessionDisabled mode, where the refresh token is a plain identity session.
type OpenSessionResponse struct {
	LoginResponse
	Session *Session `json:"session,omitempty"`
}
