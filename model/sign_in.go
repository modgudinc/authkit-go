// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "time"

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

// Failure reasons recorded in SignInEvent.FailureReason. They match the "reason"
// label of the authkit_login_failure_total counter.
const (
	// SignInFailureBadPassword: the password was wrong. It also counts toward the
	// failed-login lockout.
	SignInFailureBadPassword = "bad_password"
	// SignInFailureNoPassword: a password login to an account that has no password
	// (it signs in only through OpenSession).
	SignInFailureNoPassword = "no_password"
	// SignInFailureAccountDisabled: the account is disabled.
	SignInFailureAccountDisabled = "account_disabled"
	// SignInFailureAccountLocked: the account is locked, by the failed-login lockout
	// or by an administrator.
	SignInFailureAccountLocked = "account_locked"
	// SignInFailureNoMembership: the account checked out but has no active
	// membership in the workspace the sign-in asked for.
	SignInFailureNoMembership = "no_membership"
	// SignInFailureBadSecondFactor: the password was right but the two-factor code
	// or recovery code was wrong or already used. It also counts toward the
	// failed-login lockout.
	SignInFailureBadSecondFactor = "bad_second_factor"
)

// SignInEvent is one sign-in attempt on an existing account, recorded when
// Config.RecordSignIns is set and read back with SignInHistoryService. Attempts on
// emails that match no account are not recorded: there is no account to attach them
// to (the logger and the authkit_login_failure_total counter, reason "not_found",
// still see them). It is a read-back snapshot; treat it as read-only.
type SignInEvent struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	OccurredAt time.Time `json:"occurred_at"`
	// Method is SignInMethodPassword for a password login, or the method the
	// application passed to OpenSession ("google", "email_link", ...).
	Method string `json:"method"`
	// Succeeded reports whether the sign-in opened a session. FailureReason is ""
	// when it did, and one of the SignInFailure* reasons when it did not.
	Succeeded     bool   `json:"succeeded"`
	FailureReason string `json:"failure_reason,omitempty"`
	// Namespace is the SessionConfig.Namespace of the application the person signed
	// in to ("" when it sets none). A user's history covers every application that
	// shares the identity database.
	Namespace string `json:"namespace,omitempty"`
	// TenantID is the workspace the sign-in asked for or selected; "" when the
	// person signed in without choosing one (LoginByEmail with several workspaces).
	TenantID string `json:"tenant_id,omitempty"`
	// SessionID is the session record a successful sign-in opened, if it opened
	// one: OpenSession does whenever session support is on, and a password login
	// only with an installation. It is "" for failures. InstallationID is the
	// installation the sign-in was bound to, if any.
	SessionID      string `json:"session_id,omitempty"`
	InstallationID string `json:"installation_id,omitempty"`
	// IPAddress, UserAgent and DeviceName come from the request's SessionInfo. An
	// address that does not parse is dropped (a "host:port" keeps its host), and a
	// user agent is cut to 512 bytes.
	IPAddress  string `json:"ip_address,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	DeviceName string `json:"device_name,omitempty"`
}
