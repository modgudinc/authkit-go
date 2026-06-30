// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

// LoginRequest contains parameters for the workspace-already-known login
// (AuthService.Login). TenantID is the workspace to authenticate into; the user
// must have an active membership there. Use LoginByEmailRequest when the workspace
// is not known up front.
type LoginRequest struct {
	Email       string       `json:"email" binding:"required,email"`
	Password    string       `json:"password" binding:"required"`
	TenantID    string       `json:"tenant_id" binding:"required"`
	SessionInfo *SessionInfo `json:"session_info,omitempty"`
}

// LoginByEmailRequest contains parameters for tenant-agnostic login
// (AuthService.LoginByEmail): authenticate the global identity by email, then mint
// a workspace-scoped token. TenantID is OPTIONAL — when set (or when the identity
// has exactly one membership) a token is minted for it; otherwise the response
// carries the memberships for the caller to choose from (no token yet).
type LoginByEmailRequest struct {
	Email       string       `json:"email" binding:"required,email"`
	Password    string       `json:"password" binding:"required"`
	TenantID    string       `json:"tenant_id,omitempty"` // optional active workspace
	SessionInfo *SessionInfo `json:"session_info,omitempty"`
}

// LoginResponse contains tokens and user info after login. AccessToken/ExpiresIn
// are empty when LoginByEmail authenticated the identity but no workspace was
// selected (multiple memberships, none specified) — the caller picks one from
// Memberships and calls MintWorkspaceToken. Memberships is always populated.
type LoginResponse struct {
	AccessToken  string       `json:"access_token,omitempty"`
	RefreshToken string       `json:"refresh_token"`
	ExpiresIn    int64        `json:"expires_in,omitempty"` // Access token expiration in seconds
	User         *User        `json:"user"`
	Memberships  []Membership `json:"memberships"`
	TenantID     string       `json:"tenant_id,omitempty"` // active workspace the AccessToken is scoped to
}

// RefreshRequest contains parameters for token refresh. TenantID is the workspace
// the new access token should be scoped to (the active membership); the identity
// session is the refresh token.
type RefreshRequest struct {
	RefreshToken string       `json:"refresh_token" binding:"required"`
	TenantID     string       `json:"tenant_id" binding:"required"`
	SessionInfo  *SessionInfo `json:"session_info,omitempty"`
}

// RefreshResponse contains new tokens after successful refresh
type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	UserID       string `json:"user_id"`
	TenantID     string `json:"tenant_id"` // workspace the AccessToken is scoped to
}

// ChangePasswordRequest contains parameters for password change. It is
// identity-level (keyed by UserID only) — a credential is global.
type ChangePasswordRequest struct {
	UserID      string `json:"user_id" binding:"required"`
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}
