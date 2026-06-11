// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "time"

// Tenant represents an organization/tenant in the system
type Tenant struct {
	TenantID       string    `json:"tenant_id" db:"tenant_id"`
	Name           string    `json:"name" db:"name"`
	AllowedDomains []string  `json:"allowed_domains" db:"allowed_domains"`
	Settings       string    `json:"settings,omitempty" db:"settings"` // JSONB stored as string
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

// CreateTenantRequest contains the data needed to create a new tenant
type CreateTenantRequest struct {
	TenantID       string   // Custom tenant identifier (e.g., 'acme')
	Name           string   // Organization name
	AllowedDomains []string // Email domains allowed for this tenant
}
