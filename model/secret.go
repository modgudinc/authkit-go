// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "time"

// Secret represents a stored encrypted secret (e.g., provider API key).
// The db tags reflect the actual provider_keys columns: Key maps to the
// "provider" column and MaskedValue to "masked_key".
type Secret struct {
	TenantID       string     `json:"tenant_id" db:"tenant_id"`
	Key            string     `json:"key" db:"provider"`
	MaskedValue    string     `json:"masked_value" db:"masked_key"`
	CreatedBy      string     `json:"created_by" db:"created_by"` // User UUID (FK to users.id)
	IsValid        bool       `json:"is_valid" db:"is_valid"`
	LastVerifiedAt *time.Time `json:"last_verified_at,omitempty" db:"last_verified_at"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}

// SaveSecretRequest contains the data needed to save a secret
type SaveSecretRequest struct {
	TenantID   string // Tenant identifier
	Key        string // Secret key/name (e.g., "github", "slack", "stripe")
	PlainValue string // Plaintext value (will be encrypted by service)
	CreatedBy  string // User UUID who created the secret (FK to users.id); an update keeps the original creator
}

// SaveSecretResponse is returned after saving a secret
type SaveSecretResponse struct {
	TenantID    string    `json:"tenant_id"`
	Key         string    `json:"key"`
	MaskedValue string    `json:"masked_value"`
	CreatedBy   string    `json:"created_by"`
	IsValid     bool      `json:"is_valid"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
