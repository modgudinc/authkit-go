// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "time"

// Invitation represents an access code for inviting users to a tenant
type Invitation struct {
	Code        string    `json:"code" db:"code"`
	TenantID    string    `json:"tenant_id" db:"tenant_id"`
	CreatedBy   string    `json:"created_by" db:"created_by"` // User UUID (FK to users.id)
	Roles       []string  `json:"roles" db:"roles"`           // Array of roles to assign (stored as JSONB)
	Email       string    `json:"email" db:"email"`           // Target email address for invitation
	ExpiresAt   time.Time `json:"expires_at" db:"expires_at"`
	MaxUses     int       `json:"max_uses" db:"max_uses"`
	CurrentUses int       `json:"current_uses" db:"current_uses"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// AcceptInvitationRequest is the input to InvitationService.Accept. The
// new user's tenant and roles come from the invitation; only the display name and
// (already-hashed) password come from the caller, and Email must match the
// invitation's target.
type AcceptInvitationRequest struct {
	Code         string // Invitation code being redeemed
	Email        string // Email of the user being created; must match the invitation's target
	DisplayName  string // Display name for the new user
	PasswordHash string // Pre-hashed password (use PasswordService.HashPassword first); empty for a user without a password
}

// CreateInvitationRequest is the input to InvitationService.Create.
// The service generates the invitation code and resolves the optional defaults
// below before persisting, so callers only supply the tenant, creator, email,
// and roles.
type CreateInvitationRequest struct {
	TenantID  string         // Tenant the invitation belongs to
	CreatedBy string         // User UUID of the admin creating the invitation (FK to users.id)
	Email     string         // Target email address for this invitation (required)
	Roles     []string       // Roles to assign on signup (validated by the application layer)
	MaxUses   *int           // Optional max uses; defaults to 1 when nil or <= 0
	ExpiresIn *time.Duration // Optional lifetime; defaults to 7 days when nil
}
