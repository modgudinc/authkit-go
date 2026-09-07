// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "time"

// APIKey represents a tenant-scoped API key for SDK authentication
type APIKey struct {
	KeyID      string     `json:"key_id" db:"key_id"`
	KeyHash    string     `json:"-" db:"key_hash"` // Never expose hash in JSON
	TenantID   string     `json:"tenant_id" db:"tenant_id"`
	Name       string     `json:"name" db:"name"`
	CreatedBy  string     `json:"created_by" db:"created_by"` // User UUID (FK to users.id)
	LastUsedAt *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
}

// CreateAPIKeyRequest represents the request to create an API key
type CreateAPIKeyRequest struct {
	TenantID  string         // Tenant identifier
	CreatedBy string         // User UUID of the admin creating the key (FK to users.id)
	Name      string         // User-friendly name for the key
	ExpiresIn *time.Duration // Optional expiration; nil means the key never expires
}

// CreateAPIKeyResponse represents the service response from creating an API key
type CreateAPIKeyResponse struct {
	KeyID     string     `json:"key_id"`               // UUID v7
	APIKey    string     `json:"api_key"`              // Plaintext key (ONLY returned once)
	Name      string     `json:"name"`                 // User-friendly name
	TenantID  string     `json:"tenant_id"`            // Tenant identifier
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // Expiration timestamp (nil = never)
	CreatedAt time.Time  `json:"created_at"`           // Creation timestamp
}

// APIKeyContext represents the context extracted from a valid API key
type APIKeyContext struct {
	TenantID string `json:"tenant_id"` // Tenant identifier
	KeyID    string `json:"key_id"`    // API key identifier
}
