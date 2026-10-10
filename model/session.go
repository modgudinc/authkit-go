// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "time"

// SessionMode controls installation-bound sessions. The zero value preserves
// legacy behavior and requires no session migration.
type SessionMode uint8

const (
	SessionDisabled SessionMode = iota
	SessionOptional
	SessionRequired
)

// SessionConfig opts into installation-bound sessions. Namespace is the
// application/client boundary, independent of workspace membership.
type SessionConfig struct {
	Mode      SessionMode
	Namespace string
	// AbsoluteLifetime caps a login even when refresh tokens keep rotating.
	// Zero defaults to 30 days. RefreshExpiry controls its sliding idle lifetime.
	AbsoluteLifetime time.Duration
}

// InstallationBinding must come from enrollment verified by the embedding app.
// An ID or device name alone is not proof of possession of an installation.
type InstallationBinding struct {
	InstallationID string
}

// InstallationLoginRequest is the input to InstallationAuthService.LoginWithInstallation:
// a Login bound to the installation it is made from.
type InstallationLoginRequest struct {
	LoginRequest
	Installation InstallationBinding
}

// InstallationLoginByEmailRequest is the input to
// InstallationAuthService.LoginByEmailWithInstallation: a LoginByEmail bound to the
// installation it is made from.
type InstallationLoginByEmailRequest struct {
	LoginByEmailRequest
	Installation InstallationBinding
}

// SignInMethodPassword is the SignInMethod recorded for a session that authkit
// opened after checking a password itself (LoginWithInstallation and
// LoginByEmailWithInstallation). VerifiedLoginService.OpenSession refuses it, so
// the value always means authkit verified a password.
const SignInMethodPassword = "password"

// Session describes one login, whose ID is also its refresh-token family ID.
// It contains no credentials. TokenVersion is an internal credential-epoch
// snapshot: account credential changes invalidate the bound login permanently.
//
// InstallationID is empty for a session opened by VerifiedLoginService.OpenSession
// without an installation (a browser, for example). SignInMethod records how the
// person signed in: SignInMethodPassword, or the method the application passed to
// OpenSession ("google", "email_link", "device_code", ...).
type Session struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	Namespace         string     `json:"namespace"`
	InstallationID    string     `json:"installation_id"`
	SignInMethod      string     `json:"sign_in_method"`
	CreatedAt         time.Time  `json:"created_at"`
	LastUsedAt        time.Time  `json:"last_used_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	AbsoluteExpiresAt time.Time  `json:"absolute_expires_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	RevocationReason  string     `json:"revocation_reason,omitempty"`
	TokenVersion      int        `json:"-"`
}

// InstallationLoginResponse leaves the existing LoginResponse shape intact.
type InstallationLoginResponse struct {
	LoginResponse
	Session *Session `json:"session"`
}

// InstallationClaims contains both validated access claims and their
// authoritative installation binding.
type InstallationClaims struct {
	Claims  *JWTClaims `json:"claims"`
	Session *Session   `json:"session"`
}
