// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "github.com/golang-jwt/jwt/v5"

// JWTClaims represents the custom claims embedded in JWT access tokens.
//
// It embeds golang-jwt/v5's jwt.RegisteredClaims to carry the standard claims
// (sub, iat, exp, jti, and optional iss/aud). Because that third-party type is
// part of this struct's public surface, a major version bump of
// github.com/golang-jwt/jwt/v5 is part of authkit-go's SemVer contract and would
// be released as a breaking change. Standard fields are accessed via the embed,
// e.g. claims.Subject, claims.ExpiresAt, claims.ID (jti).
type JWTClaims struct {
	// SessionID binds an opt-in access token to one installation login.
	SessionID string   `json:"sid,omitempty"`
	UserID    string   `json:"user_id"`   // Global user identifier (UUID v7)
	Email     string   `json:"email"`     // User email address
	TenantID  string   `json:"tenant_id"` // Active workspace (tenant) this token is scoped to
	Roles     []string `json:"roles"`     // Roles in the active tenant (opaque; app-interpreted)
	// TokenVersion is the IDENTITY token version (users.token_version): a credential
	// event (password change, account disable, logout-all) bumps it and invalidates
	// every workspace's access tokens for this identity.
	TokenVersion int `json:"token_version"`
	// MembershipTokenVersion is the per-membership token version
	// (memberships.token_version): a role change or membership revoke in the active
	// tenant bumps it and invalidates only this workspace's access tokens.
	MembershipTokenVersion int `json:"membership_token_version"`
	jwt.RegisteredClaims
}
