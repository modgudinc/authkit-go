// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"time"

	"github.com/google/uuid"
)

// RefreshToken represents a stored refresh token for session management
type RefreshToken struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	UserID     uuid.UUID  `json:"user_id" db:"user_id"`
	TokenHash  string     `json:"-" db:"token_hash"`        // HMAC hash, never exposed
	FamilyID   uuid.UUID  `json:"family_id" db:"family_id"` // Lineage of one login; rotated tokens share it
	IPAddress  *string    `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent  *string    `json:"user_agent,omitempty" db:"user_agent"`
	DeviceName *string    `json:"device_name,omitempty" db:"device_name"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty" db:"revoked_at"` // Set when consumed/revoked
	ExpiresAt  time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
}

// CreateRefreshTokenRequest represents the parameters for creating a new refresh token
type CreateRefreshTokenRequest struct {
	UserID    uuid.UUID
	TokenHash string // HMAC hash of the plaintext token
	// FamilyID ties a rotated token to its lineage. Leave as uuid.Nil for a fresh
	// login (a new family is generated); set it when rotating an existing token.
	FamilyID   uuid.UUID
	IPAddress  *string
	UserAgent  *string
	DeviceName *string
	ExpiresAt  time.Time
}

// SessionInfo contains metadata about the client session
type SessionInfo struct {
	IPAddress  string `json:"ip_address"`
	UserAgent  string `json:"user_agent"`
	DeviceName string `json:"device_name"`
}
