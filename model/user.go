// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID `json:"id" db:"id"`
	Email        string    `json:"email" db:"email"`
	PasswordHash string    `json:"-" db:"password_hash"`
	TenantID     string    `json:"tenant_id" db:"tenant_id"`
	DisplayName  string    `json:"display_name" db:"display_name"`
	Roles        []string  `json:"roles" db:"roles"`
	TokenVersion int       `json:"-" db:"token_version"`

	// Account status (enable/disable - admin control)
	IsEnabled  bool       `json:"is_enabled" db:"is_enabled"`
	DisabledAt *time.Time `json:"disabled_at,omitempty" db:"disabled_at"`

	// Account status (lock/unlock - security control)
	IsLocked          bool       `json:"is_locked" db:"is_locked"`
	LockedUntil       *time.Time `json:"locked_until,omitempty" db:"locked_until"`
	FailedLoginCount  int        `json:"failed_login_count" db:"failed_login_count"`
	LastFailedLoginAt *time.Time `json:"last_failed_login_at,omitempty" db:"last_failed_login"`
	LastLoginAt       *time.Time `json:"last_login_at,omitempty" db:"last_login"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

type CreateUserRequest struct {
	Email        string
	PasswordHash string
	TenantID     string
	DisplayName  string
	Roles        []string
}

// UserStatusChange is one row of the account status-change audit trail, returned
// by UserService.StatusHistory. The library records one on every is_enabled /
// is_locked transition (admin enable/disable/lock/unlock and the automatic
// failed-login lockout). It is a read-back snapshot; treat it as read-only.
type UserStatusChange struct {
	ID uuid.UUID `json:"id"`
	// UserID is the account whose status changed.
	UserID uuid.UUID `json:"user_id"`
	// StatusType is the transition: "enable", "disable", "lock", or "unlock".
	StatusType string `json:"status_type"`
	// ChangedBy identifies the actor when known; the library leaves it nil (the
	// provenance is conveyed by ChangedByType) but it is available for callers that
	// extend the audit trail.
	ChangedBy *uuid.UUID `json:"changed_by,omitempty"`
	// ChangedByType is the provenance of the change: "admin" (an explicit mutator)
	// or "system" (the automatic failed-login lockout).
	ChangedByType string `json:"changed_by_type"`
	// ChangedAt is when the transition was recorded.
	ChangedAt time.Time `json:"changed_at"`
	// Reason is an optional free-text reason; the library leaves it nil.
	Reason *string `json:"reason,omitempty"`
	// Metadata is the JSONB detail recorded for the transition (previous/new state,
	// lock window, failed-attempt count, etc.); nil when none was recorded.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// UpdateUserRequest updates a user's display name and/or roles. UserID and TenantID
// identify the target and are required; the update is tenant-scoped (a cross-tenant
// UserID matches no row). DisplayName and Roles are each optional — a nil pointer
// leaves that column unchanged, so callers can do a partial update without first
// reading the current values. Changing Roles bumps the user's token_version
// (invalidating existing JWTs); a display-name-only update does not.
type UpdateUserRequest struct {
	UserID      uuid.UUID
	TenantID    string
	DisplayName *string
	Roles       *[]string
}
