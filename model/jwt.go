// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "github.com/golang-jwt/jwt/v5"

// JWTClaims represents the custom claims embedded in JWT access tokens
type JWTClaims struct {
	UserID       string   `json:"user_id"`       // User identifier (UUID v7)
	Email        string   `json:"email"`         // User email address
	TenantID     string   `json:"tenant_id"`     // Tenant identifier
	Roles        []string `json:"roles"`         // User roles (Admin, Member, Viewer)
	TokenVersion int      `json:"token_version"` // For invalidating all tokens
	jwt.RegisteredClaims
}
