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

// MaxTenantSettingsBytes caps the serialized size of the tenant Settings JSONB
// blob. Settings is an application-defined bag stored in a JSONB column with no
// width limit, so without a cap a very large or deeply nested map is an unbounded
// allocation / storage-DoS vector. 1 MiB is far larger than any reasonable
// settings object; an over-cap payload is rejected with model.ErrValueTooLong.
const MaxTenantSettingsBytes = 1 << 20 // 1 MiB

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
		logger: ensureLogger(logger),
	}
}

// Get retrieves a tenant by tenant_id
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - tenantID: Tenant identifier (the tenant_id chosen at creation)
//
// Returns the tenant or error if not found
func (s *TenantService) Get(ctx context.Context, tenantID string) (*model.Tenant, error) {
	s.logger.Info(ctx, "Retrieving tenant",
		"tenant_id", tenantID,
	)

	tenant, err := s.repo.GetTenant(ctx, tenantID)
	if err != nil {
		s.logger.Error(ctx, "Failed to retrieve tenant",
			"tenant_id", tenantID,
			"error", err.Error(),
		)
		return nil, sanitizeError(ctx, s.logger, "get tenant", err)
	}

	s.logger.Info(ctx, "Tenant retrieved successfully",
		"tenant_id", tenantID,
	)

	return tenant, nil
}

// GetByDomain retrieves a tenant that has the specified domain in its allowed_domains
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - domain: Email domain to search for (e.g., "acme.com")
//
// Returns the tenant or error if not found
func (s *TenantService) GetByDomain(ctx context.Context, domain string) (*model.Tenant, error) {
	s.logger.Info(ctx, "Retrieving tenant by domain",
		"domain", domain,
	)

	// Normalize domain (lowercase, trim whitespace)
	domain = strings.ToLower(strings.TrimSpace(domain))

	tenant, err := s.repo.GetTenantByDomain(ctx, domain)
	if err != nil {
		s.logger.Error(ctx, "Failed to retrieve tenant by domain",
			"domain", domain,
			"error", err.Error(),
		)
		return nil, sanitizeError(ctx, s.logger, "get tenant by domain", err)
	}

	s.logger.Info(ctx, "Tenant retrieved successfully by domain",
		"domain", domain,
		"tenant_id", tenant.TenantID,
	)

	return tenant, nil
}

// Create creates a new tenant/organization
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
func (s *TenantService) Create(ctx context.Context, req model.CreateTenantRequest) (*model.Tenant, error) {
	s.logger.Info(ctx, "Creating tenant",
		"tenant_id", req.TenantID,
		"name", req.Name,
		"allowed_domains", strings.Join(req.AllowedDomains, ","),
	)

	// The id is the primary key the caller chooses and the name is what people see;
	// neither may be blank.
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Name = strings.TrimSpace(req.Name)
	if req.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required: %w", model.ErrInvalidInput)
	}
	if req.Name == "" {
		return nil, fmt.Errorf("name is required: %w", model.ErrInvalidInput)
	}

	// A tenant must have at least one allowed domain (the schema enforces this with
	// a NOT NULL + non-empty CHECK; reject up front with a clear error instead of
	// surfacing a raw constraint violation).
	if len(req.AllowedDomains) == 0 {
		return nil, fmt.Errorf("at least one allowed_domain is required: %w", model.ErrInvalidInput)
	}

	// Validate and normalize all allowed_domains. Domains are lowercased on write
	// so the (already-lowercased) lookups in ValidateDomainAccess and
	// GetByDomain match — fulfilling the documented case-insensitive
	// matching contract.
	for i, domain := range req.AllowedDomains {
		normalized := strings.ToLower(strings.TrimSpace(domain))
		if err := s.validateDomain(normalized); err != nil {
			return nil, fmt.Errorf("invalid allowed_domain '%s': %s: %w", domain, err.Error(), model.ErrInvalidInput)
		}
		req.AllowedDomains[i] = normalized
	}

	// Create tenant
	err := s.repo.CreateTenant(ctx, req)
	if err != nil {
		s.logger.Error(ctx, "Failed to create tenant",
			"tenant_id", req.TenantID,
			"error", err.Error(),
		)
		return nil, sanitizeError(ctx, s.logger, "create tenant", err)
	}

	// Retrieve the created tenant from the primary: a replica may not have it yet.
	tenant, err := s.repo.GetTenantFromPrimary(ctx, req.TenantID)
	if err != nil {
		s.logger.Error(ctx, "Failed to retrieve created tenant",
			"tenant_id", req.TenantID,
			"error", err.Error(),
		)
		return nil, sanitizeError(ctx, s.logger, "retrieve created tenant", err)
	}

	s.logger.Info(ctx, "Tenant created successfully",
		"tenant_id", req.TenantID,
		"name", req.Name,
	)

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
	s.logger.Info(ctx, "Updating tenant settings",
		"tenant_id", tenantID,
	)

	// Validate settings can be marshaled to JSON
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		s.logger.Error(ctx, "Invalid settings JSON",
			"tenant_id", tenantID,
			"error", err.Error(),
		)
		// Unserializable settings are a caller-input problem (e.g. an unsupported
		// value type), not an internal fault — return a matchable input sentinel
		// (400-class) instead of leaking the raw json error.
		return fmt.Errorf("invalid settings: %w", model.ErrInvalidInput)
	}

	// Bound the serialized size: Settings is a JSONB column with no width limit, so
	// reject an oversized blob up front rather than allowing an unbounded write.
	if len(settingsJSON) > MaxTenantSettingsBytes {
		s.logger.Warn(ctx, "Tenant settings exceed size cap",
			"tenant_id", tenantID,
			"size_bytes", len(settingsJSON),
			"max_bytes", MaxTenantSettingsBytes,
		)
		return fmt.Errorf("tenant settings exceed the %d-byte maximum: %w", MaxTenantSettingsBytes, model.ErrValueTooLong)
	}

	// Update settings
	err = s.repo.UpdateSettings(ctx, tenantID, string(settingsJSON))
	if err != nil {
		s.logger.Error(ctx, "Failed to update tenant settings",
			"tenant_id", tenantID,
			"error", err.Error(),
		)
		return sanitizeError(ctx, s.logger, "update tenant settings", err)
	}

	s.logger.Info(ctx, "Tenant settings updated successfully",
		"tenant_id", tenantID,
	)

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
	s.logger.Info(ctx, "Updating tenant name",
		"tenant_id", tenantID,
		"name", name,
	)

	err := s.repo.UpdateName(ctx, tenantID, name)
	if err != nil {
		s.logger.Error(ctx, "Failed to update tenant name",
			"tenant_id", tenantID,
			"error", err.Error(),
		)
		return sanitizeError(ctx, s.logger, "update tenant name", err)
	}

	s.logger.Info(ctx, "Tenant name updated successfully",
		"tenant_id", tenantID,
	)

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
	s.logger.Info(ctx, "Setting allowed domains",
		"tenant_id", tenantID,
		"domains", strings.Join(domains, ","),
	)

	// A tenant must keep at least one allowed domain (NOT NULL + non-empty CHECK in
	// the schema); reject an empty list up front rather than emitting a raw
	// constraint violation.
	if len(domains) == 0 {
		return fmt.Errorf("at least one allowed_domain is required")
	}

	// Validate and normalize all domains (lowercased on write; see Create).
	for i, domain := range domains {
		normalized := strings.ToLower(strings.TrimSpace(domain))
		if err := s.validateDomain(normalized); err != nil {
			s.logger.Error(ctx, "Invalid domain format",
				"tenant_id", tenantID,
				"domain", domain,
				"error", err.Error(),
			)
			return fmt.Errorf("invalid domain '%s': %w", domain, err)
		}
		domains[i] = normalized
	}

	err := s.repo.SetAllowedDomains(ctx, tenantID, domains)
	if err != nil {
		s.logger.Error(ctx, "Failed to set allowed domains",
			"tenant_id", tenantID,
			"error", err.Error(),
		)
		return sanitizeError(ctx, s.logger, "set allowed domains", err)
	}

	s.logger.Info(ctx, "Allowed domains set successfully",
		"tenant_id", tenantID,
	)

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
	s.logger.Info(ctx, "Adding allowed domain",
		"tenant_id", tenantID,
		"domain", domain,
	)

	// Normalize on write (lowercased; see Create) so it matches lookups.
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Validate domain format
	if err := s.validateDomain(domain); err != nil {
		s.logger.Error(ctx, "Invalid domain format",
			"tenant_id", tenantID,
			"domain", domain,
			"error", err.Error(),
		)
		return fmt.Errorf("invalid domain: %w", err)
	}

	// Add domain (repository handles duplicate check)
	err := s.repo.AddAllowedDomain(ctx, tenantID, domain)
	if err != nil {
		s.logger.Error(ctx, "Failed to add allowed domain",
			"tenant_id", tenantID,
			"domain", domain,
			"error", err.Error(),
		)
		return sanitizeError(ctx, s.logger, "add allowed domain", err)
	}

	s.logger.Info(ctx, "Allowed domain added successfully",
		"tenant_id", tenantID,
		"domain", domain,
	)

	return nil
}

// List lists all tenants (admin/debug operation)
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//
// Returns a list of all tenants ordered by created_at DESC
func (s *TenantService) List(ctx context.Context) ([]*model.Tenant, error) {
	s.logger.Info(ctx, "Listing all tenants")

	tenants, err := s.repo.ListAllTenants(ctx)
	if err != nil {
		s.logger.Error(ctx, "Failed to list tenants",
			"error", err.Error(),
		)
		return nil, sanitizeError(ctx, s.logger, "list tenants", err)
	}

	s.logger.Info(ctx, "Tenants listed successfully",
		"count", len(tenants),
	)

	return tenants, nil
}

// Exists checks if a tenant exists by tenant_id
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - tenantID: Tenant identifier
//
// Returns true if tenant exists, false otherwise
func (s *TenantService) Exists(ctx context.Context, tenantID string) (bool, error) {
	exists, err := s.repo.TenantExists(ctx, tenantID)
	if err != nil {
		s.logger.Error(ctx, "Failed to check tenant existence",
			"tenant_id", tenantID,
			"error", err.Error(),
		)
		return false, sanitizeError(ctx, s.logger, "check tenant existence", err)
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
		return fmt.Errorf("invalid email format: %w", model.ErrInvalidInput)
	}

	// Get tenant
	tenant, err := s.repo.GetTenant(ctx, tenantID)
	if err != nil {
		return sanitizeError(ctx, s.logger, "validate domain access", err)
	}

	// Check if domain is in allowed_domains
	for _, allowedDomain := range tenant.AllowedDomains {
		if allowedDomain == domain {
			return nil // Domain is allowed
		}
	}

	return fmt.Errorf("email domain '%s' is not allowed for tenant '%s': %w", domain, tenantID, model.ErrInvalidInput)
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
