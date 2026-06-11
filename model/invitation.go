// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "time"

// Invitation represents an access code for inviting users to a tenant
type Invitation struct {
	Code        string    `json:"code" db:"code"`
	TenantID    string    `json:"tenant_id" db:"tenant_id"`
	CreatedBy   string    `json:"created_by" db:"created_by"`
	Roles       []string  `json:"roles" db:"roles"` // Array of roles to assign (stored as JSONB)
	Email       string    `json:"email" db:"email"` // Target email address for invitation
	ExpiresAt   time.Time `json:"expires_at" db:"expires_at"`
	MaxUses     int       `json:"max_uses" db:"max_uses"`
	CurrentUses int       `json:"current_uses" db:"current_uses"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// CreateInvitationRequest contains the data needed to create a new invitation
type CreateInvitationRequest struct {
	Code      string    // Cryptographically secure random code (20 characters)
	TenantID  string    // Tenant identifier
	CreatedBy string    // User UUID of the admin creating the invitation
	Roles     []string  // Roles to assign (validated by application layer)
	Email     string    // Target email address for this invitation (required)
	ExpiresAt time.Time // Expiration timestamp (typically NOW() + 7 days)
	MaxUses   int       // Maximum number of times the code can be used (default: 1)
}
