// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/model"
)

// APIKeyService handles API key-related business logic including
// creation, validation, and revocation of tenant-scoped API keys.
type APIKeyService struct {
	repo       *repository.Repository
	hmacSecret string
	logger     logger.Logger
}

// NewAPIKeyService creates a new APIKeyService instance
func NewAPIKeyService(repo *repository.Repository, hmacSecret string, logger logger.Logger) *APIKeyService {
	return &APIKeyService{
		repo:       repo,
		hmacSecret: hmacSecret,
		logger:     logger,
	}
}

// CreateAPIKey creates a new API key for a tenant
//
// Flow:
// 1. Generate UUID v7 for key_id (time-ordered)
// 2. Generate cryptographically secure 32-byte key with sk_live_ prefix
// 3. Compute HMAC-SHA256 hash of key
// 4. Store key_hash in database (never store plaintext)
// 5. Return plaintext key to caller (only time it's visible)
//
// IMPORTANT: The plaintext API key is returned only once and never stored
func (s *APIKeyService) CreateAPIKey(ctx context.Context, req model.CreateAPIKeyRequest) (*model.CreateAPIKeyResponse, error) {
	if s.logger != nil {
		s.logger.Info("Creating API key",
			"tenant_id", req.TenantID,
			"name", req.Name,
		)
	}

	// Generate key ID (UUID v7 - time-ordered)
	keyID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key ID: %w", err)
	}

	// Generate cryptographically secure API key
	// Format: "sk_live_" prefix + 32 random characters
	apiKey, err := s.generateSecureKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate API key: %w", err)
	}

	// Compute HMAC-SHA256 hash of the API key
	keyHash := s.computeHMAC(apiKey)

	// Apply expiration if provided.
	var expiresAt *time.Time
	if req.ExpiresIn != nil {
		expiry := time.Now().Add(*req.ExpiresIn)
		expiresAt = &expiry
	}

	// Create API key in database
	err = s.repo.CreateAPIKey(ctx, repository.InsertAPIKeyParams{
		KeyID:     keyID.String(),
		KeyHash:   keyHash,
		TenantID:  req.TenantID,
		Name:      req.Name,
		CreatedBy: req.CreatedBy,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}

	// Format response
	response := &model.CreateAPIKeyResponse{
		KeyID:     keyID.String(),
		APIKey:    apiKey, // Plaintext key - ONLY returned once
		Name:      req.Name,
		TenantID:  req.TenantID,
		ExpiresAt: expiresAt, // nil = never expires
		CreatedAt: time.Now(),
	}

	if s.logger != nil {
		s.logger.Info("API key created successfully",
			"key_id", keyID.String(),
			"tenant_id", req.TenantID,
			"name", req.Name,
		)
	}

	return response, nil
}

// ValidateAPIKey validates an API key and returns the associated tenant context
//
// Flow:
// 1. Validate key format (sk_live_ prefix, correct length)
// 2. Compute hash of provided key
// 3. Lookup in database via hash
// 4. Check expiry
// 5. Update last_used_at (async, non-blocking)
// 6. Return tenant context
//
// Returns the API key context (tenant_id, key_id) or error
func (s *APIKeyService) ValidateAPIKey(ctx context.Context, apiKey string) (*model.APIKeyContext, error) {
	// Validate key format. The specific reason is logged, not returned, so the
	// caller only sees a generic invalid-key error.
	if err := s.validateKeyFormat(apiKey); err != nil {
		if s.logger != nil {
			s.logger.Warn("API key format validation failed", "error", err.Error())
		}
		return nil, fmt.Errorf("invalid API key format: %w", model.ErrInvalidAPIKey)
	}

	// Compute hash of provided key
	keyHash := s.computeHMAC(apiKey)

	// Lookup API key by hash
	key, err := s.repo.GetAPIKeyByHash(ctx, keyHash)
	if err != nil {
		// Untrusted input: log at Warn to avoid error-level floods from invalid keys.
		if s.logger != nil {
			s.logger.Warn("API key not found", "error", err.Error())
		}
		return nil, model.ErrInvalidAPIKey
	}

	// Check if expired (GetAPIKeyByHash already filters expired keys, but double-check)
	if key.ExpiresAt != nil && key.ExpiresAt.Before(time.Now()) {
		if s.logger != nil {
			s.logger.Warn("API key is expired",
				"key_id", key.KeyID,
				"expires_at", key.ExpiresAt.Format(time.RFC3339),
			)
		}
		return nil, fmt.Errorf("API key is expired: %w", model.ErrInvalidAPIKey)
	}

	// Update last_used_at as a bounded, best-effort background write (see
	// runBoundedLastUsedUpdate): detached from the request, timeout-bounded, and
	// capped in concurrency so a burst of validations can't fan out unbounded.
	keyID, keyTenantID := key.KeyID, key.TenantID
	runBoundedLastUsedUpdate(ctx, s.logger, "api key", func(uctx context.Context) error {
		return s.repo.UpdateAPIKeyLastUsed(uctx, keyID, keyTenantID)
	})

	return &model.APIKeyContext{
		TenantID: key.TenantID,
		KeyID:    key.KeyID,
	}, nil
}

// ListAPIKeys lists all API keys for a tenant
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - tenantID: Tenant identifier
//   - includeExpired: Whether to include expired keys in the list
//
// Returns a list of API keys (without key_hash or plaintext key) or error
func (s *APIKeyService) ListAPIKeys(ctx context.Context, tenantID string, includeExpired bool) ([]*model.APIKey, error) {
	keys, err := s.repo.ListAPIKeys(ctx, tenantID, includeExpired)
	return keys, sanitizeError(s.logger, "list api keys", err)
}

// GetAPIKey retrieves a specific API key by key_id within a tenant
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - keyID: API key identifier (UUID)
//   - tenantID: Owning tenant; the lookup is scoped to it so one tenant
//     cannot read another tenant's key by guessing its id (prevents IDOR)
//
// Returns the API key metadata (without plaintext key) or error
func (s *APIKeyService) GetAPIKey(ctx context.Context, keyID, tenantID string) (*model.APIKey, error) {
	key, err := s.repo.GetAPIKey(ctx, keyID, tenantID)
	return key, sanitizeError(s.logger, "get api key", err)
}

// RevokeAPIKey revokes (deletes) an API key within a tenant
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - keyID: API key identifier (UUID)
//   - tenantID: Owning tenant; the delete is scoped to it so one tenant
//     cannot revoke another tenant's key by guessing its id (prevents IDOR)
//
// Returns error if key not found (or not owned by the tenant) or on database failure
func (s *APIKeyService) RevokeAPIKey(ctx context.Context, keyID, tenantID string) error {
	if s.logger != nil {
		s.logger.Info("Revoking API key", "key_id", keyID, "tenant_id", tenantID)
	}

	err := s.repo.DeleteAPIKey(ctx, keyID, tenantID)
	if err != nil {
		return sanitizeError(s.logger, "revoke api key", err)
	}

	if s.logger != nil {
		s.logger.Info("API key revoked successfully", "key_id", keyID, "tenant_id", tenantID)
	}

	return nil
}

// CountByTenant returns the count of active (non-expired) API keys for a tenant
func (s *APIKeyService) CountByTenant(ctx context.Context, tenantID string) (int, error) {
	n, err := s.repo.CountAPIKeysByTenant(ctx, tenantID)
	return n, sanitizeError(s.logger, "count api keys", err)
}

// CleanupExpiredKeys removes expired API keys from the database
//
// Should be run periodically (e.g., via cron job) to maintain database hygiene
// Returns the number of expired keys deleted
func (s *APIKeyService) CleanupExpiredKeys(ctx context.Context) (int64, error) {
	if s.logger != nil {
		s.logger.Info("Cleaning up expired API keys")
	}

	count, err := s.repo.DeleteExpiredAPIKeys(ctx)
	if err != nil {
		return 0, sanitizeError(s.logger, "cleanup expired api keys", err)
	}

	if s.logger != nil {
		s.logger.Info("Expired API keys cleaned up", "count", count)
	}

	return count, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// generateSecureKey generates a cryptographically secure API key
// Format: "sk_live_" prefix + 32 random characters
func (s *APIKeyService) generateSecureKey() (string, error) {
	const (
		prefix       = "sk_live_"
		charset      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		randomLength = 32
	)

	randomChars := make([]byte, randomLength)
	charsetLen := len(charset)
	for i := range randomChars {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(charsetLen)))
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %w", err)
		}
		randomChars[i] = charset[num.Int64()]
	}

	return prefix + string(randomChars), nil
}

// computeHMAC computes the HMAC-SHA256 hash of an API key
func (s *APIKeyService) computeHMAC(apiKey string) string {
	h := hmac.New(sha256.New, []byte(s.hmacSecret))
	h.Write([]byte(apiKey))
	return hex.EncodeToString(h.Sum(nil))
}

// validateKeyFormat validates that an API key has the correct format
// Expected format: sk_live_<32-chars> (total 40 characters)
func (s *APIKeyService) validateKeyFormat(apiKey string) error {
	const (
		prefix       = "sk_live_"
		expectedLen  = 40 // "sk_live_" (8) + 32 random chars
		randomLength = 32
	)

	// Check prefix
	if !strings.HasPrefix(apiKey, prefix) {
		return fmt.Errorf("invalid API key format: missing prefix")
	}

	// Check length
	if len(apiKey) != expectedLen {
		return fmt.Errorf("invalid API key format: incorrect length (expected %d, got %d)", expectedLen, len(apiKey))
	}

	// Check random part contains only valid characters
	randomPart := apiKey[len(prefix):]
	if len(randomPart) != randomLength {
		return fmt.Errorf("invalid API key format: incorrect random part length")
	}

	// Validate characters (a-z, A-Z, 0-9)
	for _, ch := range randomPart {
		if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') {
			return fmt.Errorf("invalid API key format: contains invalid character")
		}
	}

	return nil
}
