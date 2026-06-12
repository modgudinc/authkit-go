// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/model"
)

// Secret Repository Methods:
//
// Key Management:
// - SaveSecret       - Creates or updates an encrypted secret
// - ListSecrets      - Lists all secrets for a tenant (masked values only)
// - GetEncryptedSecret - Retrieves the encrypted value for decryption
// - DeleteSecret     - Deletes a secret by key
//
// Verification:
// - UpdateSecretVerified - Updates the last_verified_at timestamp

// ============================================================================
// SaveSecret - Creates or updates an encrypted secret
// Uses UPSERT pattern: INSERT ... ON CONFLICT ... DO UPDATE
// ============================================================================
func (r *Repository) SaveSecret(
	ctx context.Context,
	tenantID, key, encryptedValue, maskedValue string,
	createdBy uuid.UUID,
) (*model.Secret, error) {
	query := `
		INSERT INTO {{schema}}.provider_keys
			(tenant_id, provider, encrypted_key, masked_key, created_by, is_valid)
		VALUES ($1, $2, $3, $4, $5, true)
		ON CONFLICT (tenant_id, provider)
		DO UPDATE SET
			encrypted_key = EXCLUDED.encrypted_key,
			masked_key = EXCLUDED.masked_key,
			is_valid = true,
			updated_at = NOW()
		RETURNING tenant_id, provider, masked_key, created_by, last_verified_at, is_valid, created_at, updated_at
	`

	var secret model.Secret
	var lastVerifiedAt sql.NullTime

	err := r.rw.QueryRowContext(ctx, r.q(query), tenantID, key, encryptedValue, maskedValue, createdBy).Scan(
		&secret.TenantID,
		&secret.Key,
		&secret.MaskedValue,
		&secret.CreatedBy,
		&lastVerifiedAt,
		&secret.IsValid,
		&secret.CreatedAt,
		&secret.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to save secret: %w", err)
	}

	if lastVerifiedAt.Valid {
		secret.LastVerifiedAt = &lastVerifiedAt.Time
	}

	return &secret, nil
}

// ============================================================================
// ListSecrets - Lists all secrets for a tenant
// Returns masked values only (encrypted values are not returned)
// Ordered by key ASC
// ============================================================================
func (r *Repository) ListSecrets(ctx context.Context, tenantID string) ([]*model.Secret, error) {
	query := `
		SELECT tenant_id, provider, masked_key, created_by, last_verified_at, is_valid, created_at, updated_at
		FROM {{schema}}.provider_keys
		WHERE tenant_id = $1
		ORDER BY provider ASC
	`

	rows, err := r.ro.QueryContext(ctx, r.q(query), tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var secrets []*model.Secret
	for rows.Next() {
		var secret model.Secret
		var lastVerifiedAt sql.NullTime
		var maskedValue sql.NullString

		err := rows.Scan(
			&secret.TenantID,
			&secret.Key,
			&maskedValue,
			&secret.CreatedBy,
			&lastVerifiedAt,
			&secret.IsValid,
			&secret.CreatedAt,
			&secret.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan secret row: %w", err)
		}

		if lastVerifiedAt.Valid {
			secret.LastVerifiedAt = &lastVerifiedAt.Time
		}
		if maskedValue.Valid {
			secret.MaskedValue = maskedValue.String
		}

		secrets = append(secrets, &secret)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating secret rows: %w", err)
	}

	return secrets, nil
}

// ============================================================================
// GetEncryptedSecret - Retrieves the encrypted value for a secret
// Used by the service layer for decryption
// ============================================================================
func (r *Repository) GetEncryptedSecret(ctx context.Context, tenantID, key string) (string, error) {
	query := `
		SELECT encrypted_key
		FROM {{schema}}.provider_keys
		WHERE tenant_id = $1 AND provider = $2
	`

	var encryptedValue string
	err := r.ro.QueryRowContext(ctx, r.q(query), tenantID, key).Scan(&encryptedValue)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("secret not found: %w", model.ErrNotFound)
		}
		return "", fmt.Errorf("failed to get secret: %w", err)
	}

	return encryptedValue, nil
}

// ============================================================================
// DeleteSecret - Deletes a secret by tenant and key
// Returns error if secret not found
// ============================================================================
func (r *Repository) DeleteSecret(ctx context.Context, tenantID, key string) error {
	query := `
		DELETE FROM {{schema}}.provider_keys
		WHERE tenant_id = $1 AND provider = $2
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), tenantID, key)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("secret not found: %s", key)
	}

	return nil
}

// ============================================================================
// CountSecretsByTenant - Returns the count of secrets for a tenant
// ============================================================================
func (r *Repository) CountSecretsByTenant(ctx context.Context, tenantID string) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM {{schema}}.provider_keys
		WHERE tenant_id = $1
	`

	var count int
	err := r.ro.QueryRowContext(ctx, r.q(query), tenantID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count secrets: %w", err)
	}

	return count, nil
}

// ============================================================================
// UpdateSecretVerified - Updates the last_verified_at timestamp
// Called after successful secret verification (e.g., API key test)
// Also sets is_valid = true
// ============================================================================
func (r *Repository) UpdateSecretVerified(ctx context.Context, tenantID, key string) error {
	query := `
		UPDATE {{schema}}.provider_keys
		SET last_verified_at = NOW(), is_valid = true
		WHERE tenant_id = $1 AND provider = $2
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), tenantID, key)
	if err != nil {
		return fmt.Errorf("failed to update secret verified: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("secret not found: %s", key)
	}

	return nil
}
