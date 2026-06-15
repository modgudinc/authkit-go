// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTClaims represents the custom claims embedded in JWT access tokens.
//
// It embeds golang-jwt/v5's jwt.RegisteredClaims to carry the standard claims
// (sub, iat, exp, jti, and optional iss/aud). Because that third-party type is
// part of this struct's public surface, a major version bump of
// github.com/golang-jwt/jwt/v5 is part of authkit-go's SemVer contract and would
// be released as a breaking change. Standard fields are accessed via the embed,
// e.g. claims.Subject, claims.ExpiresAt, claims.ID (jti).
type JWTClaims struct {
	UserID       uuid.UUID `json:"user_id"`       // User identifier (UUID v7)
	Email        string    `json:"email"`         // User email address
	TenantID     string    `json:"tenant_id"`     // Tenant identifier
	Roles        []string  `json:"roles"`         // User roles (Admin, Member, Viewer)
	TokenVersion int       `json:"token_version"` // For invalidating all tokens
	jwt.RegisteredClaims
}
