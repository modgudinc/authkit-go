// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/model"
)

// TenantService handles tenant-related business logic including
// tenant creation, retrieval, settings management, and domain management.
type TenantService struct {
	repo   *repository.Repository
	logger logger.Logger
}

// NewTenantService creates a new TenantService instance
func NewTenantService(repo *repository.Repository, logger logger.Logger) *TenantService {
	return &TenantService{
		repo:   repo,
		logger: logger,
	}
}

// GetTenant retrieves a tenant by tenant_id
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - tenantID: Tenant identifier (primary email domain)
//
// Returns the tenant or error if not found
func (s *TenantService) GetTenant(ctx context.Context, tenantID string) (*model.Tenant, error) {
	if s.logger != nil {
		s.logger.Info("Retrieving tenant",
			"tenant_id", tenantID,
		)
	}

	tenant, err := s.repo.GetTenant(ctx, tenantID)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to retrieve tenant",
				"tenant_id", tenantID,
				"error", err.Error(),
			)
		}
		return nil, sanitizeError(nil, "get tenant", err)
	}

	if s.logger != nil {
		s.logger.Info("Tenant retrieved successfully",
			"tenant_id", tenantID,
		)
	}

	return tenant, nil
}

// GetTenantByDomain retrieves a tenant that has the specified domain in its allowed_domains
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - domain: Email domain to search for (e.g., "acme.com")
//
// Returns the tenant or error if not found
func (s *TenantService) GetTenantByDomain(ctx context.Context, domain string) (*model.Tenant, error) {
	if s.logger != nil {
		s.logger.Info("Retrieving tenant by domain",
			"domain", domain,
		)
	}

	// Normalize domain (lowercase, trim whitespace)
	domain = strings.ToLower(strings.TrimSpace(domain))

	tenant, err := s.repo.GetTenantByDomain(ctx, domain)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to retrieve tenant by domain",
				"domain", domain,
				"error", err.Error(),
			)
		}
		return nil, sanitizeError(nil, "get tenant by domain", err)
	}

	if s.logger != nil {
		s.logger.Info("Tenant retrieved successfully by domain",
			"domain", domain,
			"tenant_id", tenant.TenantID,
		)
	}

	return tenant, nil
}

// CreateTenant creates a new tenant/organization
//
// Flow:
// 1. Validate allowed_domains (all must be valid domains)
// 2. Create tenant in database
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - req: CreateTenantRequest with tenant details
//
// Returns the created tenant or error
func (s *TenantService) CreateTenant(ctx context.Context, req model.CreateTenantRequest) (*model.Tenant, error) {
	if s.logger != nil {
		s.logger.Info("Creating tenant",
			"tenant_id", req.TenantID,
			"name", req.Name,
			"allowed_domains", strings.Join(req.AllowedDomains, ","),
		)
	}

	// A tenant must have at least one allowed domain (the schema enforces this with
	// a NOT NULL + non-empty CHECK; reject up front with a clear error instead of
	// surfacing a raw constraint violation).
	if len(req.AllowedDomains) == 0 {
		return nil, fmt.Errorf("at least one allowed_domain is required")
	}

	// Validate and normalize all allowed_domains. Domains are lowercased on write
	// so the (already-lowercased) lookups in ValidateDomainAccess and
	// GetTenantByDomain match — fulfilling the documented case-insensitive
	// matching contract.
	for i, domain := range req.AllowedDomains {
		normalized := strings.ToLower(strings.TrimSpace(domain))
		if err := s.validateDomain(normalized); err != nil {
			return nil, fmt.Errorf("invalid allowed_domain '%s': %w", domain, err)
		}
		req.AllowedDomains[i] = normalized
	}

	// Create tenant
	err := s.repo.CreateTenant(ctx, req)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to create tenant",
				"tenant_id", req.TenantID,
				"error", err.Error(),
			)
		}
		return nil, sanitizeError(nil, "create tenant", err)
	}

	// Retrieve the created tenant
	tenant, err := s.repo.GetTenant(ctx, req.TenantID)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to retrieve created tenant",
				"tenant_id", req.TenantID,
				"error", err.Error(),
			)
		}
		return nil, sanitizeError(nil, "retrieve created tenant", err)
	}

	if s.logger != nil {
		s.logger.Info("Tenant created successfully",
			"tenant_id", req.TenantID,
			"name", req.Name,
		)
	}

	return tenant, nil
}

// UpdateSettings updates tenant settings (JSONB)
//
// Flow:
// 1. Validate settings is valid JSON
// 2. Marshal settings to JSON string
// 3. Update in database
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - tenantID: Tenant identifier
//   - settings: Settings map to store as JSONB
//
// Returns error if validation or update fails
func (s *TenantService) UpdateSettings(ctx context.Context, tenantID string, settings map[string]interface{}) error {
	if s.logger != nil {
		s.logger.Info("Updating tenant settings",
			"tenant_id", tenantID,
		)
	}

	// Validate settings can be marshaled to JSON
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Invalid settings JSON",
				"tenant_id", tenantID,
				"error", err.Error(),
			)
		}
		return fmt.Errorf("invalid settings: %w", err)
	}

	// Update settings
	err = s.repo.UpdateSettings(ctx, tenantID, string(settingsJSON))
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to update tenant settings",
				"tenant_id", tenantID,
				"error", err.Error(),
			)
		}
		return sanitizeError(nil, "update tenant settings", err)
	}

	if s.logger != nil {
		s.logger.Info("Tenant settings updated successfully",
			"tenant_id", tenantID,
		)
	}

	return nil
}

// UpdateName updates the tenant name
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - tenantID: Tenant identifier
//   - name: New tenant name
//
// Returns error if update fails
func (s *TenantService) UpdateName(ctx context.Context, tenantID, name string) error {
	if s.logger != nil {
		s.logger.Info("Updating tenant name",
			"tenant_id", tenantID,
			"name", name,
		)
	}

	err := s.repo.UpdateName(ctx, tenantID, name)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to update tenant name",
				"tenant_id", tenantID,
				"error", err.Error(),
			)
		}
		return sanitizeError(nil, "update tenant name", err)
	}

	if s.logger != nil {
		s.logger.Info("Tenant name updated successfully",
			"tenant_id", tenantID,
		)
	}

	return nil
}

// SetAllowedDomains replaces the entire allowed_domains list
//
// Flow:
// 1. Validate all domain formats
// 2. Replace the allowed_domains array in database
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - tenantID: Tenant identifier
//   - domains: New list of allowed domains
//
// Returns error if validation or update fails
func (s *TenantService) SetAllowedDomains(ctx context.Context, tenantID string, domains []string) error {
	if s.logger != nil {
		s.logger.Info("Setting allowed domains",
			"tenant_id", tenantID,
			"domains", strings.Join(domains, ","),
		)
	}

	// A tenant must keep at least one allowed domain (NOT NULL + non-empty CHECK in
	// the schema); reject an empty list up front rather than emitting a raw
	// constraint violation.
	if len(domains) == 0 {
		return fmt.Errorf("at least one allowed_domain is required")
	}

	// Validate and normalize all domains (lowercased on write; see CreateTenant).
	for i, domain := range domains {
		normalized := strings.ToLower(strings.TrimSpace(domain))
		if err := s.validateDomain(normalized); err != nil {
			if s.logger != nil {
				s.logger.Error("Invalid domain format",
					"tenant_id", tenantID,
					"domain", domain,
					"error", err.Error(),
				)
			}
			return fmt.Errorf("invalid domain '%s': %w", domain, err)
		}
		domains[i] = normalized
	}

	err := s.repo.SetAllowedDomains(ctx, tenantID, domains)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to set allowed domains",
				"tenant_id", tenantID,
				"error", err.Error(),
			)
		}
		return sanitizeError(nil, "set allowed domains", err)
	}

	if s.logger != nil {
		s.logger.Info("Allowed domains set successfully",
			"tenant_id", tenantID,
		)
	}

	return nil
}

// AddAllowedDomain adds a new allowed email domain to a tenant
//
// Flow:
// 1. Validate domain format
// 2. Add domain to tenant (repository prevents duplicates)
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - tenantID: Tenant identifier
//   - domain: Email domain to add (e.g., "example.com")
//
// Returns error if validation or update fails
func (s *TenantService) AddAllowedDomain(ctx context.Context, tenantID, domain string) error {
	if s.logger != nil {
		s.logger.Info("Adding allowed domain",
			"tenant_id", tenantID,
			"domain", domain,
		)
	}

	// Normalize on write (lowercased; see CreateTenant) so it matches lookups.
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Validate domain format
	if err := s.validateDomain(domain); err != nil {
		if s.logger != nil {
			s.logger.Error("Invalid domain format",
				"tenant_id", tenantID,
				"domain", domain,
				"error", err.Error(),
			)
		}
		return fmt.Errorf("invalid domain: %w", err)
	}

	// Add domain (repository handles duplicate check)
	err := s.repo.AddAllowedDomain(ctx, tenantID, domain)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to add allowed domain",
				"tenant_id", tenantID,
				"domain", domain,
				"error", err.Error(),
			)
		}
		return sanitizeError(nil, "add allowed domain", err)
	}

	if s.logger != nil {
		s.logger.Info("Allowed domain added successfully",
			"tenant_id", tenantID,
			"domain", domain,
		)
	}

	return nil
}

// ListTenants lists all tenants (admin/debug operation)
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//
// Returns a list of all tenants ordered by created_at DESC
func (s *TenantService) ListTenants(ctx context.Context) ([]*model.Tenant, error) {
	if s.logger != nil {
		s.logger.Info("Listing all tenants")
	}

	tenants, err := s.repo.ListAllTenants(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to list tenants",
				"error", err.Error(),
			)
		}
		return nil, sanitizeError(nil, "list tenants", err)
	}

	if s.logger != nil {
		s.logger.Info("Tenants listed successfully",
			"count", len(tenants),
		)
	}

	return tenants, nil
}

// TenantExists checks if a tenant exists by tenant_id
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - tenantID: Tenant identifier
//
// Returns true if tenant exists, false otherwise
func (s *TenantService) TenantExists(ctx context.Context, tenantID string) (bool, error) {
	exists, err := s.repo.TenantExists(ctx, tenantID)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to check tenant existence",
				"tenant_id", tenantID,
				"error", err.Error(),
			)
		}
		return false, sanitizeError(nil, "check tenant existence", err)
	}

	return exists, nil
}

// ValidateDomainAccess checks if an email domain is allowed for a tenant
//
// Flow:
// 1. Extract domain from email
// 2. Get tenant
// 3. Check if domain is in allowed_domains list
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - email: Email address to validate
//   - tenantID: Tenant identifier
//
// Returns error if domain is not allowed
func (s *TenantService) ValidateDomainAccess(ctx context.Context, email, tenantID string) error {
	// Extract domain from email
	domain := s.extractDomain(email)
	if domain == "" {
		return fmt.Errorf("invalid email format")
	}

	// Get tenant
	tenant, err := s.repo.GetTenant(ctx, tenantID)
	if err != nil {
		return sanitizeError(s.logger, "validate domain access", err)
	}

	// Check if domain is in allowed_domains
	for _, allowedDomain := range tenant.AllowedDomains {
		if allowedDomain == domain {
			return nil // Domain is allowed
		}
	}

	return fmt.Errorf("email domain '%s' is not allowed for tenant '%s'", domain, tenantID)
}

// ============================================================================
// Helper Functions
// ============================================================================

// domainRegex matches a valid domain name: at least one label + dot + TLD,
// allowing subdomains (mail.example.com, api.v2.example.com). Compiled once at
// package load rather than on every validateDomain call.
var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// validateDomain validates that a string is a valid domain name
// Validates format: domain.tld (e.g., "example.com", "mail.google.com")
func (s *TenantService) validateDomain(domain string) error {
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain format: %s", domain)
	}

	return nil
}

// extractDomain extracts the domain part from an email address
// Example: "user@example.com" -> "example.com"
func (s *TenantService) extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(parts[1])
}
