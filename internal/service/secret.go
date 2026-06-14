// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/model"
)

// secretCipherV1Prefix is the ciphertext format marker. It is prepended to the
// base64 blob; base64 never contains ':', so its presence unambiguously tags the
// format and leaves room for future schemes (v2, …) without ambiguity. Every
// stored value must carry it: ciphertext is always authenticated against the
// (tenant_id, key) AAD — there is no unauthenticated legacy path.
const secretCipherV1Prefix = "v1:"

// secretAAD binds a ciphertext to the row it belongs to, so a value copied to a
// different (tenant_id, key) — e.g. by DB tampering under the shared key — fails
// authentication instead of decrypting as another tenant's secret.
func secretAAD(tenantID, key string) []byte {
	return []byte(tenantID + "\x00" + key)
}

// SecretService handles encrypted secret management including
// creation, retrieval, and deletion of tenant-scoped secrets.
//
// Secrets are encrypted using AES-256-GCM before storage.
// The encryption key must be 32 bytes (256 bits).
type SecretService struct {
	repo          *repository.Repository
	encryptionKey []byte // 32-byte AES-256 key
	logger        logger.Logger
}

// NewSecretService creates a new SecretService instance
//
// Parameters:
//   - repo: Repository for database operations
//   - encryptionKey: 32-byte AES-256 encryption key (decoded from base64)
//   - logger: Optional logger for structured logging
func NewSecretService(repo *repository.Repository, encryptionKey []byte, logger logger.Logger) *SecretService {
	return &SecretService{
		repo:          repo,
		encryptionKey: encryptionKey,
		logger:        logger,
	}
}

// SaveSecret encrypts and stores a secret
//
// Flow:
// 1. Validate encryption key is configured (32 bytes)
// 2. Encrypt plaintext value using AES-256-GCM
// 3. Generate masked value for display
// 4. Upsert to database (INSERT ... ON CONFLICT ... DO UPDATE)
// 5. Return saved secret metadata (without encrypted value)
//
// IMPORTANT: The plaintext value is encrypted before storage and never stored in plaintext
func (s *SecretService) SaveSecret(ctx context.Context, req model.SaveSecretRequest) (*model.SaveSecretResponse, error) {
	if s.logger != nil {
		s.logger.Info("Saving secret",
			"tenant_id", req.TenantID,
			"key", req.Key,
		)
	}

	// Validate encryption key
	if len(s.encryptionKey) != 32 {
		return nil, fmt.Errorf("save secret: %w", model.ErrSecretEncryptionKeyMissing)
	}

	// Encrypt the plaintext value, binding it to its (tenant, key) context.
	encryptedValue, err := s.encrypt(req.PlainValue, req.TenantID, req.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Generate masked value for display
	maskedValue := maskValue(req.PlainValue)

	// Save to repository
	secret, err := s.repo.SaveSecret(ctx, req.TenantID, req.Key, encryptedValue, maskedValue, req.CreatedBy)
	if err != nil {
		return nil, sanitizeError(s.logger, "save secret", err)
	}

	if s.logger != nil {
		s.logger.Info("Secret saved successfully",
			"tenant_id", req.TenantID,
			"key", req.Key,
		)
	}

	return &model.SaveSecretResponse{
		TenantID:    secret.TenantID,
		Key:         secret.Key,
		MaskedValue: secret.MaskedValue,
		CreatedBy:   secret.CreatedBy.String(),
		IsValid:     secret.IsValid,
		CreatedAt:   secret.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   secret.UpdatedAt.Format(time.RFC3339),
	}, nil
}

// GetSecret decrypts and returns a secret's plain value
//
// Flow:
// 1. Retrieve encrypted value from database
// 2. Decrypt using AES-256-GCM
// 3. Return plaintext value
//
// Returns error if secret not found or decryption fails
func (s *SecretService) GetSecret(ctx context.Context, tenantID, key string) (string, error) {
	// Validate encryption key
	if len(s.encryptionKey) != 32 {
		return "", fmt.Errorf("get secret: %w", model.ErrSecretEncryptionKeyMissing)
	}

	// Get encrypted value from repository
	encryptedValue, err := s.repo.GetEncryptedSecret(ctx, tenantID, key)
	if err != nil {
		return "", sanitizeError(s.logger, "get secret", err)
	}

	// Decrypt the value, authenticating it against its (tenant, key) context.
	plainValue, err := s.decrypt(encryptedValue, tenantID, key)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to decrypt secret",
				"tenant_id", tenantID,
				"key", key,
				"error", err.Error(),
			)
		}
		return "", fmt.Errorf("failed to decrypt secret: %w", err)
	}

	return plainValue, nil
}

// ListSecrets lists all secrets for a tenant
//
// Returns masked values only (not decrypted)
// Ordered by key ASC
func (s *SecretService) ListSecrets(ctx context.Context, tenantID string) ([]*model.Secret, error) {
	secrets, err := s.repo.ListSecrets(ctx, tenantID)
	return secrets, sanitizeError(s.logger, "list secrets", err)
}

// DeleteSecret removes a secret
//
// Returns error if secret not found
func (s *SecretService) DeleteSecret(ctx context.Context, tenantID, key string) error {
	if s.logger != nil {
		s.logger.Info("Deleting secret",
			"tenant_id", tenantID,
			"key", key,
		)
	}

	err := s.repo.DeleteSecret(ctx, tenantID, key)
	if err != nil {
		return sanitizeError(s.logger, "delete secret", err)
	}

	if s.logger != nil {
		s.logger.Info("Secret deleted successfully",
			"tenant_id", tenantID,
			"key", key,
		)
	}

	return nil
}

// MarkVerified updates the last_verified_at timestamp
//
// Called after successful secret verification (e.g., API key test)
// Also sets is_valid = true
func (s *SecretService) MarkVerified(ctx context.Context, tenantID, key string) error {
	return sanitizeError(s.logger, "mark secret verified", s.repo.UpdateSecretVerified(ctx, tenantID, key))
}

// CountByTenant returns the count of secrets for a tenant
func (s *SecretService) CountByTenant(ctx context.Context, tenantID string) (int, error) {
	n, err := s.repo.CountSecretsByTenant(ctx, tenantID)
	return n, sanitizeError(s.logger, "count secrets", err)
}

// ============================================================================
// Helper Functions
// ============================================================================

// encrypt encrypts plaintext using AES-256-GCM, binding the ciphertext to its
// (tenantID, key) context via the GCM additional authenticated data.
//
// Output is "v1:" + base64(nonce (12 bytes) + encrypted data + auth tag (16 bytes)).
func (s *SecretService) encrypt(plaintext, tenantID, key string) (string, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt with context-binding AAD and prepend nonce to ciphertext.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), secretAAD(tenantID, key))
	return secretCipherV1Prefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts ciphertext using AES-256-GCM, authenticating it against its
// (tenantID, key) context via the GCM additional authenticated data. The
// ciphertext must carry the secretCipherV1Prefix marker; anything else is
// rejected as malformed. There is deliberately no unauthenticated fallback: an
// attacker who can write the column must not be able to strip the marker to
// bypass the context binding.
func (s *SecretService) decrypt(ciphertext, tenantID, key string) (string, error) {
	rest, ok := strings.CutPrefix(ciphertext, secretCipherV1Prefix)
	if !ok {
		return "", fmt.Errorf("unrecognized secret ciphertext format")
	}
	aad := secretAAD(tenantID, key)

	data, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, aad)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// maskValue generates a masked version of a value for display
//
// Format: prefix (up to '_') + '************' + last 4 chars
// Example: "cur_1234567890abcdef" -> "cur_************cdef"
// Example: "sk-abc123def456" -> "sk-************f456"
//
// For short values (< 12 chars) the whole value is masked: revealing a known
// prefix plus the last 4 characters of, say, an 8-character secret would expose
// most of it, so partial reveal is reserved for values long enough that it
// leaks only a small fraction.
func maskValue(value string) string {
	if len(value) < 12 {
		return "************"
	}

	// Find prefix (up to first underscore or hyphen)
	prefix := ""
	for i, ch := range value {
		if ch == '_' || ch == '-' {
			if i > 0 && i < len(value)-4 {
				prefix = value[:i+1] // Include the delimiter
			}
			break
		}
	}

	// Get last 4 characters
	suffix := value[len(value)-4:]

	return prefix + "************" + suffix
}
