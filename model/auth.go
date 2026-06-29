// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

// LoginRequest contains parameters for user login
type LoginRequest struct {
	Email       string       `json:"email" binding:"required,email"`
	Password    string       `json:"password" binding:"required"`
	TenantID    string       `json:"tenant_id" binding:"required"`
	SessionInfo *SessionInfo `json:"session_info,omitempty"`
}

// LoginResponse contains tokens and user info after successful login
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"` // Access token expiration in seconds
	User         *User  `json:"user"`
}

// RefreshRequest contains parameters for token refresh
type RefreshRequest struct {
	RefreshToken string       `json:"refresh_token" binding:"required"`
	SessionInfo  *SessionInfo `json:"session_info,omitempty"`
}

// RefreshResponse contains new tokens after successful refresh
type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	UserID       string `json:"user_id"`
}

// ChangePasswordRequest contains parameters for password change.
//
// TenantID is required: the change is scoped to (UserID, TenantID) so a
// caller-supplied user id from another tenant cannot be targeted. Pass the tenant
// the caller is authorized for.
type ChangePasswordRequest struct {
	UserID      string `json:"user_id" binding:"required"`
	TenantID    string `json:"tenant_id" binding:"required"`
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}
