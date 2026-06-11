// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"
	"github.com/modgudinc/authkit-go/model"
)

// Tenant Repository Methods:
//
// Tenant Management:
// - CreateTenant           - Creates a new tenant/organization
// - GetTenant              - Retrieves a tenant by tenant_id (custom identifier)
// - GetTenantByDomain      - Retrieves a tenant by searching for a domain in allowed_domains
// - TenantExists           - Checks if a tenant exists by tenant_id
// - ListAllTenants         - Lists all tenants (admin/debug use only)
//
// Domain Management:
// - AddAllowedDomain       - Adds a new allowed email domain to a tenant
//
// Settings Management:
// - UpdateSettings         - Updates tenant settings (JSONB)

// ============================================================================
// CreateTenant - Creates a new tenant/organization
// ============================================================================
func (r *Repository) CreateTenant(ctx context.Context, req model.CreateTenantRequest) error {
	query := `
		INSERT INTO authkit.tenants (
			tenant_id, name, allowed_domains, created_at, updated_at
		)
		VALUES ($1, $2, $3, NOW(), NOW())
	`

	_, err := r.rw.ExecContext(ctx, r.q(query),
		req.TenantID,
		req.Name,
		pq.Array(req.AllowedDomains),
	)
	if err != nil {
		return fmt.Errorf("failed to create tenant: %w", err)
	}

	return nil
}

// ============================================================================
// GetTenant - Retrieves a tenant by tenant_id (custom identifier)
// ============================================================================
func (r *Repository) GetTenant(ctx context.Context, tenantID string) (*model.Tenant, error) {
	query := `
		SELECT tenant_id, name, allowed_domains,
		       COALESCE(settings::text, '{}'), created_at, updated_at
		FROM authkit.tenants
		WHERE tenant_id = $1
	`

	var tenant model.Tenant

	err := r.ro.QueryRowContext(ctx, r.q(query), tenantID).Scan(
		&tenant.TenantID,
		&tenant.Name,
		pq.Array(&tenant.AllowedDomains),
		&tenant.Settings,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("tenant not found: %w", model.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	return &tenant, nil
}

// ============================================================================
// GetTenantByDomain - Retrieves a tenant by searching for a domain in allowed_domains
// Uses PostgreSQL's ANY operator to search within the allowed_domains array
// ============================================================================
func (r *Repository) GetTenantByDomain(ctx context.Context, domain string) (*model.Tenant, error) {
	query := `
		SELECT tenant_id, name, allowed_domains,
		       COALESCE(settings::text, '{}'), created_at, updated_at
		FROM authkit.tenants
		WHERE $1 = ANY(allowed_domains)
		LIMIT 1
	`

	var tenant model.Tenant

	err := r.ro.QueryRowContext(ctx, r.q(query), domain).Scan(
		&tenant.TenantID,
		&tenant.Name,
		pq.Array(&tenant.AllowedDomains),
		&tenant.Settings,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("tenant not found with domain: %w", model.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get tenant by domain: %w", err)
	}

	return &tenant, nil
}

// ============================================================================
// TenantExists - Checks if a tenant exists by tenant_id
// ============================================================================
func (r *Repository) TenantExists(ctx context.Context, tenantID string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM authkit.tenants WHERE tenant_id = $1)`

	var exists bool
	err := r.ro.QueryRowContext(ctx, r.q(query), tenantID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check tenant existence: %w", err)
	}

	return exists, nil
}

// ============================================================================
// ListAllTenants - Lists all tenants (admin/debug use only)
// Ordered by created_at DESC (newest first)
// ============================================================================
func (r *Repository) ListAllTenants(ctx context.Context) ([]*model.Tenant, error) {
	query := `
		SELECT tenant_id, name, allowed_domains,
		       COALESCE(settings::text, '{}'), created_at, updated_at
		FROM authkit.tenants
		ORDER BY created_at DESC
	`

	rows, err := r.ro.QueryContext(ctx, r.q(query))
	if err != nil {
		return nil, fmt.Errorf("failed to list all tenants: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var tenants []*model.Tenant
	for rows.Next() {
		var tenant model.Tenant

		err := rows.Scan(
			&tenant.TenantID,
			&tenant.Name,
			pq.Array(&tenant.AllowedDomains),
			&tenant.Settings,
			&tenant.CreatedAt,
			&tenant.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan tenant row: %w", err)
		}

		tenants = append(tenants, &tenant)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating tenant rows: %w", err)
	}

	return tenants, nil
}

// ============================================================================
// AddAllowedDomain - Adds a new allowed email domain to a tenant
// Uses PostgreSQL array_append to add domain only if not already present
// ============================================================================
func (r *Repository) AddAllowedDomain(ctx context.Context, tenantID, domain string) error {
	query := `
		UPDATE authkit.tenants
		SET allowed_domains = array_append(allowed_domains, $2),
		    updated_at = NOW()
		WHERE tenant_id = $1
		  AND NOT ($2 = ANY(allowed_domains))  -- Prevent duplicates
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), tenantID, domain)
	if err != nil {
		return fmt.Errorf("failed to add allowed domain: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("tenant not found or domain already exists: %s", tenantID)
	}

	return nil
}

// ============================================================================
// UpdateName - Updates tenant name
// ============================================================================
func (r *Repository) UpdateName(ctx context.Context, tenantID, name string) error {
	query := `
		UPDATE authkit.tenants
		SET name = $2,
		    updated_at = NOW()
		WHERE tenant_id = $1
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), tenantID, name)
	if err != nil {
		return fmt.Errorf("failed to update tenant name: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}

	return nil
}

// ============================================================================
// SetAllowedDomains - Replaces the entire allowed_domains array
// ============================================================================
func (r *Repository) SetAllowedDomains(ctx context.Context, tenantID string, domains []string) error {
	query := `
		UPDATE authkit.tenants
		SET allowed_domains = $2,
		    updated_at = NOW()
		WHERE tenant_id = $1
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), tenantID, pq.Array(domains))
	if err != nil {
		return fmt.Errorf("failed to update allowed domains: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}

	return nil
}

// ============================================================================
// UpdateSettings - Updates tenant settings (JSONB)
// Accepts settings as JSON string
// ============================================================================
func (r *Repository) UpdateSettings(ctx context.Context, tenantID, settingsJSON string) error {
	query := `
		UPDATE authkit.tenants
		SET settings = $2::jsonb,
		    updated_at = NOW()
		WHERE tenant_id = $1
	`

	result, err := r.rw.ExecContext(ctx, r.q(query), tenantID, settingsJSON)
	if err != nil {
		return fmt.Errorf("failed to update tenant settings: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}

	return nil
}
