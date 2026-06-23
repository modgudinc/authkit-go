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
		logger:        ensureLogger(logger),
	}
}

// Save encrypts and stores a secret
//
// Flow:
// 1. Validate encryption key is configured (32 bytes)
// 2. Encrypt plaintext value using AES-256-GCM
// 3. Generate masked value for display
// 4. Upsert to database (INSERT ... ON CONFLICT ... DO UPDATE)
// 5. Return saved secret metadata (without encrypted value)
//
// IMPORTANT: The plaintext value is encrypted before storage and never stored in plaintext
func (s *SecretService) Save(ctx context.Context, req model.SaveSecretRequest) (*model.SaveSecretResponse, error) {
	s.logger.Info(ctx, "Saving secret",
		"tenant_id", req.TenantID,
		"key", req.Key,
	)

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
		return nil, sanitizeError(ctx, s.logger, "save secret", err)
	}

	s.logger.Info(ctx, "Secret saved successfully",
		"tenant_id", req.TenantID,
		"key", req.Key,
	)

	return &model.SaveSecretResponse{
		TenantID:    secret.TenantID,
		Key:         secret.Key,
		MaskedValue: secret.MaskedValue,
		CreatedBy:   secret.CreatedBy,
		IsValid:     secret.IsValid,
		CreatedAt:   secret.CreatedAt,
		UpdatedAt:   secret.UpdatedAt,
	}, nil
}

// Get decrypts and returns a secret's plain value
//
// Flow:
// 1. Retrieve encrypted value from database
// 2. Decrypt using AES-256-GCM
// 3. Return plaintext value
//
// Returns error if secret not found or decryption fails
func (s *SecretService) Get(ctx context.Context, tenantID, key string) (string, error) {
	// Validate encryption key
	if len(s.encryptionKey) != 32 {
		return "", fmt.Errorf("get secret: %w", model.ErrSecretEncryptionKeyMissing)
	}

	// Get encrypted value from repository
	encryptedValue, err := s.repo.GetEncryptedSecret(ctx, tenantID, key)
	if err != nil {
		return "", sanitizeError(ctx, s.logger, "get secret", err)
	}

	// Decrypt the value, authenticating it against its (tenant, key) context.
	plainValue, err := s.decrypt(encryptedValue, tenantID, key)
	if err != nil {
		s.logger.Error(ctx, "Failed to decrypt secret",
			"tenant_id", tenantID,
			"key", key,
			"error", err.Error(),
		)
		// A decrypt/authentication failure is a server-side integrity fault (corrupt
		// ciphertext, wrong key, or tampering), not caller input — map it to the
		// matchable ErrInternal sentinel rather than leaking the raw crypto error.
		return "", fmt.Errorf("decrypt secret: %w", model.ErrInternal)
	}

	return plainValue, nil
}

// List lists all secrets for a tenant
//
// Returns masked values only (not decrypted)
// Ordered by key ASC
func (s *SecretService) List(ctx context.Context, tenantID string) ([]*model.Secret, error) {
	secrets, err := s.repo.ListSecrets(ctx, tenantID)
	return secrets, sanitizeError(ctx, s.logger, "list secrets", err)
}

// Delete removes a secret
//
// Returns error if secret not found
func (s *SecretService) Delete(ctx context.Context, tenantID, key string) error {
	s.logger.Info(ctx, "Deleting secret",
		"tenant_id", tenantID,
		"key", key,
	)

	err := s.repo.DeleteSecret(ctx, tenantID, key)
	if err != nil {
		return sanitizeError(ctx, s.logger, "delete secret", err)
	}

	s.logger.Info(ctx, "Secret deleted successfully",
		"tenant_id", tenantID,
		"key", key,
	)

	return nil
}

// MarkVerified updates the last_verified_at timestamp
//
// Called after successful secret verification (e.g., API key test)
// Also sets is_valid = true
func (s *SecretService) MarkVerified(ctx context.Context, tenantID, key string) error {
	return sanitizeError(ctx, s.logger, "mark secret verified", s.repo.UpdateSecretVerified(ctx, tenantID, key))
}

// Count returns the count of secrets for a tenant
func (s *SecretService) Count(ctx context.Context, tenantID string) (int, error) {
	n, err := s.repo.CountSecretsByTenant(ctx, tenantID)
	return n, sanitizeError(ctx, s.logger, "count secrets", err)
}

// ============================================================================
// Helper Functions
// ============================================================================

// encrypt encrypts plaintext using AES-256-GCM, binding the ciphertext to its
// (tenantID, key) context via the GCM additional authenticated data.
//
// Output is "v1:" + base64(nonce (12 bytes) + encrypted data + auth tag (16 bytes)).
//
// The 96-bit nonce is random per call under a single, long-lived key. Random GCM
// nonces stay collision-safe well past any realistic tenant-secret write volume
// (the birthday bound is on the order of 2^32 encryptions per key), so this is safe
// at expected scale. Note there is no built-in key-rotation / re-encryption helper
// and no per-tenant key derivation: rotating SecretConfig.EncryptionKey requires
// decrypting with the old key and re-encrypting with the new one at the application
// layer (see SECURITY.md, "Rotation Expectations").
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

// maskValue generates a masked version of a value for display.
//
// Format: optional short type tag (up to the first '_' or '-') + '************' +
// last 4 chars. Example: "cur_1234567890abcdef" -> "cur_************cdef";
// "sk-abc123def456" -> "sk-************f456".
//
// It is deliberately conservative and only ever reveals a *short* leading type
// tag plus the last 4 characters:
//   - Values under 12 chars are fully masked: a known tag plus the last 4 chars
//     of, say, an 8-char secret would expose most of it.
//   - The tag is only revealed when the first delimiter sits within the first few
//     characters (a real type tag like "sk-"/"cur_") AND a masked gap of at least
//     a few characters remains before the revealed suffix. A delimiter that sits
//     late in the string is not a type tag, so revealing everything up to it would
//     leak the bulk of the secret — that case falls back to suffix-only masking.
func maskValue(value string) string {
	const (
		mask         = "************"
		revealSuffix = 4
		// A type tag is short ("sk_", "cur_", "pk-"); never treat a long leading
		// run as a prefix.
		maxPrefixLen = 5
		// Require at least this many masked characters between the revealed prefix
		// and the revealed suffix, so the two can never add up to most of the value.
		minMaskedGap = 4
	)

	if len(value) < 12 {
		return mask
	}

	prefix := ""
	for i, ch := range value {
		if i >= maxPrefixLen {
			break // no short type tag near the start; reveal only the suffix
		}
		if ch == '_' || ch == '-' {
			if i > 0 && i+1+revealSuffix+minMaskedGap <= len(value) {
				prefix = value[:i+1] // include the delimiter
			}
			break
		}
	}

	return prefix + mask + value[len(value)-revealSuffix:]
}
