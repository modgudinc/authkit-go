// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/model"
)

// InsertAPIKeyParams contains the data needed to insert a new API key. It is a
// repository-internal persistence DTO — callers use APIKeyService.CreateAPIKey
// with model.CreateAPIKeyRequest, which the service maps onto this type.
type InsertAPIKeyParams struct {
	KeyID     string
	KeyHash   string
	TenantID  string
	Name      string
	CreatedBy uuid.UUID
	ExpiresAt *time.Time
}

// API Key Repository Methods:
//
// Key Management:
// - Create           - Creates a new API key with hashed key storage
// - Get              - Retrieves an API key by key_id
// - GetByHash        - Validates an API key by hash (for authentication)
// - List             - Lists all API keys for a tenant
// - Delete           - Deletes an API key by key_id
//
// Usage Tracking:
// - UpdateLastUsed   - Updates the last_used_at timestamp
//
// Maintenance:
// - DeleteExpired    - Cleanup method to remove expired API keys

// ============================================================================
// Create - Creates a new API key with hashed key storage
// IMPORTANT: The key_hash must be a HMAC-SHA256 hash of the API key
// Never store plaintext API keys
// ============================================================================
func (r *Repository) CreateAPIKey(ctx context.Context, req InsertAPIKeyParams) error {
	query := `
		INSERT INTO {{schema}}.api_keys (
			key_id, key_hash, tenant_id, name, created_by, expires_at, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	now := time.Now()
	_, err := r.rw.ExecContext(ctx, r.q(query),
		req.KeyID,
		req.KeyHash,
		req.TenantID,
		req.Name,
		req.CreatedBy,
		req.ExpiresAt,
		now,
	)
	if err != nil {
		return fmt.Errorf("failed to create api key: %w", err)
	}

	return nil
}

// ============================================================================
// Get - Retrieves an API key by key_id within a tenant
// Returns the full APIKey record including metadata.
// Scoped by tenant_id so a caller cannot read another tenant's key by id.
// ============================================================================
func (r *Repository) GetAPIKey(ctx context.Context, keyID, tenantID string) (*model.APIKey, error) {
	query := `
		SELECT key_id, key_hash, tenant_id, name, created_by, last_used_at, expires_at, created_at
		FROM {{schema}}.api_keys
		WHERE key_id = $1
		  AND tenant_id = $2
	`

	var apiKey model.APIKey
	var lastUsedAt, expiresAt *time.Time

	err := r.ro.QueryRowContext(ctx, r.q(query), keyID, tenantID).Scan(
		&apiKey.KeyID,
		&apiKey.KeyHash,
		&apiKey.TenantID,
		&apiKey.Name,
		&apiKey.CreatedBy,
		&lastUsedAt,
		&expiresAt,
		&apiKey.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("api key not found: %w", model.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get api key: %w", err)
	}

	apiKey.LastUsedAt = lastUsedAt
	apiKey.ExpiresAt = expiresAt

	return &apiKey, nil
}

// ============================================================================
// GetByHash - Validates an API key by its hash (for authentication)
// Checks that:
// 1. A key exists with the given hash
// 2. The key has not expired (if expires_at is set)
// Returns the APIKey if valid, error otherwise
//
// Reads from the PRIMARY (rw), not a read replica: this is the credential
// validation path run immediately after a key is created, where replica lag
// could spuriously reject a freshly minted key. Do not switch to r.ro without
// accepting that auth-failure risk.
// ============================================================================
func (r *Repository) GetAPIKeyByHash(ctx context.Context, keyHash string) (*model.APIKey, error) {
	query := `
		SELECT key_id, key_hash, tenant_id, name, created_by, last_used_at, expires_at, created_at
		FROM {{schema}}.api_keys
		WHERE key_hash = $1
		  AND (expires_at IS NULL OR expires_at > $2)
	`

	var apiKey model.APIKey
	var lastUsedAt, expiresAt *time.Time

	err := r.rw.QueryRowContext(ctx, r.q(query), keyHash, time.Now()).Scan(
		&apiKey.KeyID,
		&apiKey.KeyHash,
		&apiKey.TenantID,
		&apiKey.Name,
		&apiKey.CreatedBy,
		&lastUsedAt,
		&expiresAt,
		&apiKey.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("api key not found or expired: %w", model.ErrInvalidAPIKey)
		}
		return nil, fmt.Errorf("failed to validate api key: %w", err)
	}

	apiKey.LastUsedAt = lastUsedAt
	apiKey.ExpiresAt = expiresAt

	return &apiKey, nil
}

// ============================================================================
// List - Lists all API keys for a tenant
// Ordered by created_at DESC (newest first)
// Does not return expired keys by default
// ============================================================================
func (r *Repository) ListAPIKeys(ctx context.Context, tenantID string, includeExpired bool) ([]*model.APIKey, error) {
	var query string
	if includeExpired {
		query = `
			SELECT key_id, key_hash, tenant_id, name, created_by, last_used_at, expires_at, created_at
			FROM {{schema}}.api_keys
			WHERE tenant_id = $1
			ORDER BY created_at DESC
		`
	} else {
		query = `
			SELECT key_id, key_hash, tenant_id, name, created_by, last_used_at, expires_at, created_at
			FROM {{schema}}.api_keys
			WHERE tenant_id = $1
			  AND (expires_at IS NULL OR expires_at > $2)
			ORDER BY created_at DESC
		`
	}

	var rows *sql.Rows
	var err error

	if includeExpired {
		rows, err = r.ro.QueryContext(ctx, r.q(query), tenantID)
	} else {
		rows, err = r.ro.QueryContext(ctx, r.q(query), tenantID, time.Now())
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list api keys: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var apiKeys []*model.APIKey
	for rows.Next() {
		var apiKey model.APIKey
		var lastUsedAt, expiresAt *time.Time

		err := rows.Scan(
			&apiKey.KeyID,
			&apiKey.KeyHash,
			&apiKey.TenantID,
			&apiKey.Name,
			&apiKey.CreatedBy,
			&lastUsedAt,
			&expiresAt,
			&apiKey.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan api key row: %w", err)
		}

		apiKey.LastUsedAt = lastUsedAt
		apiKey.ExpiresAt = expiresAt

		apiKeys = append(apiKeys, &apiKey)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating api key rows: %w", err)
	}

	return apiKeys, nil
}

// ============================================================================
// UpdateLastUsed - Updates the last_used_at timestamp for an API key
// Called after successful API key authentication to track usage.
// Scoped by tenant_id for defense in depth (the tenant is known from the
// hash-verified lookup that precedes this call).
// ============================================================================
func (r *Repository) UpdateAPIKeyLastUsed(ctx context.Context, keyID, tenantID string) error {
	query := `
		UPDATE {{schema}}.api_keys
		SET last_used_at = $1
		WHERE key_id = $2
		  AND tenant_id = $3
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), time.Now(), keyID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to update api key last used: %w", err)
	}

	return requireRowsAffected(result, fmt.Errorf("api key %s not found: %w", keyID, model.ErrNotFound))
}

// ============================================================================
// Delete - Deletes an API key by key_id within a tenant
// Permanently removes the key from the database.
// Scoped by tenant_id so a caller cannot revoke another tenant's key by id.
// ============================================================================
func (r *Repository) DeleteAPIKey(ctx context.Context, keyID, tenantID string) error {
	query := `
		DELETE FROM {{schema}}.api_keys
		WHERE key_id = $1
		  AND tenant_id = $2
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), keyID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete api key: %w", err)
	}

	return requireRowsAffected(result, fmt.Errorf("api key %s not found: %w", keyID, model.ErrNotFound))
}

// ============================================================================
// CountAPIKeysByTenant - Returns the count of active (non-expired) API keys for a tenant
// ============================================================================
func (r *Repository) CountAPIKeysByTenant(ctx context.Context, tenantID string) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM {{schema}}.api_keys
		WHERE tenant_id = $1
		  AND (expires_at IS NULL OR expires_at > $2)
	`

	var count int
	err := r.ro.QueryRowContext(ctx, r.q(query), tenantID, time.Now()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count api keys: %w", err)
	}

	return count, nil
}

// ============================================================================
// DeleteExpired - Cleanup method to remove expired API keys
// Should be run periodically (e.g., via cron job) to maintain database hygiene
// Returns the number of expired keys deleted
// ============================================================================
func (r *Repository) DeleteExpiredAPIKeys(ctx context.Context) (int64, error) {
	query := `
		DELETE FROM {{schema}}.api_keys
		WHERE expires_at IS NOT NULL
		  AND expires_at <= $1
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired api keys: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected, nil
}
