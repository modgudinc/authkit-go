// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "time"

// Membership status values.
const (
	MembershipActive    = "active"
	MembershipSuspended = "suspended"
)

// Membership is the user<->tenant graph row: which global identity belongs to
// which tenant, and with which roles. Roles are OPAQUE strings — authkit stores
// them; the embedding application interprets them (authkit owns the graph, the app
// owns the policy). TokenVersion is the per-membership token version: a role change
// or revoke in this tenant invalidates only this workspace's access tokens,
// independently of the identity-level users.token_version.
type Membership struct {
	UserID       string    `json:"user_id" db:"user_id"`
	TenantID     string    `json:"tenant_id" db:"tenant_id"`
	Roles        []string  `json:"roles" db:"roles"`
	TokenVersion int       `json:"-" db:"token_version"`
	Status       string    `json:"status" db:"status"` // MembershipActive | MembershipSuspended
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// IsActive reports whether the membership is usable (status == active).
func (m *Membership) IsActive() bool { return m.Status == MembershipActive }

// AddMembershipRequest grants (or upserts) a user's membership in a tenant with the
// given roles. Idempotent on (UserID, TenantID): re-adding updates the roles.
type AddMembershipRequest struct {
	UserID   string
	TenantID string
	Roles    []string
}
