// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "time"

// User is the GLOBAL identity: it carries no tenant_id and no roles — those
// live on Membership. email is globally unique. TokenVersion is the identity-level
// token version (credential events invalidate every workspace's access tokens).
type User struct {
	ID           string `json:"id" db:"id"`
	Email        string `json:"email" db:"email"`
	PasswordHash string `json:"-" db:"password_hash"`
	DisplayName  string `json:"display_name" db:"display_name"`
	TokenVersion int    `json:"-" db:"token_version"`

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

// CreateUserRequest creates a GLOBAL identity. No tenant or roles — grant tenant
// access separately via MembershipService.Add. Email must be globally unique.
type CreateUserRequest struct {
	Email        string
	PasswordHash string
	DisplayName  string
}

// UserStatusChange is one row of the account status-change audit trail, returned
// by UserService.StatusHistory. The library records one on every is_enabled /
// is_locked transition (admin enable/disable/lock/unlock and the automatic
// failed-login lockout). It is a read-back snapshot; treat it as read-only.
type UserStatusChange struct {
	ID string `json:"id"`
	// UserID is the account whose status changed.
	UserID string `json:"user_id"`
	// StatusType is the transition: "enable", "disable", "lock", or "unlock".
	StatusType string `json:"status_type"`
	// ChangedBy identifies the actor when known; the library leaves it nil (the
	// provenance is conveyed by ChangedByType) but it is available for callers that
	// extend the audit trail.
	ChangedBy *string `json:"changed_by,omitempty"`
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

// UpdateUserRequest updates a global identity's display name. UserID is required;
// DisplayName is optional (a nil pointer leaves it unchanged). Roles are no longer
// here — they are per-tenant; change them via MembershipService.UpdateRoles.
type UpdateUserRequest struct {
	UserID      string
	DisplayName *string
}
