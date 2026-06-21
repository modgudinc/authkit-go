// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
)

// MaxOTPValidationAttempts is the number of failed validation attempts allowed
// per issued OTP before it is invalidated. Because OTPs are short numeric codes,
// this lockout is what prevents online brute force; once exceeded the caller must
// request a new code.
const MaxOTPValidationAttempts = 5

// OTPService handles OTP generation, validation, and lifecycle management
// with rate limiting and single-use enforcement
type OTPService struct {
	repo              otpRepository
	rateLimitDuration time.Duration // Minimum time between OTP generation attempts
	hmacSecret        string        // HMAC-SHA256 secret for hashing OTP codes at rest
	logger            logger.Logger
	metrics           metrics.Metrics
}

type otpRepository interface {
	GetVerificationCode(ctx context.Context, tenantID, email, purpose string) (*repository.VerificationCode, error)
	UpsertVerificationCode(ctx context.Context, req repository.CreateVerificationCodeRequest, rateLimit time.Duration) (bool, error)
	ConsumeVerificationCode(ctx context.Context, tenantID, email, code, purpose string, maxAttempts int) (repository.OTPConsumeResult, error)
	DeleteVerificationCode(ctx context.Context, tenantID, email, purpose string) error
	DeleteExpiredVerificationCodes(ctx context.Context) (int64, error)
}

// NewOTPService creates a new OTP service instance.
//
// hmacSecret keys the HMAC-SHA256 used to hash OTP codes at rest; when empty,
// Generate and Validate return model.ErrOTPSecretMissing. metrics is optional and
// may be nil.
func NewOTPService(repo *repository.Repository, rateLimitDuration time.Duration, hmacSecret string, logger logger.Logger, metrics metrics.Metrics) *OTPService {
	return &OTPService{
		repo:              repo,
		rateLimitDuration: rateLimitDuration,
		hmacSecret:        hmacSecret,
		logger:            ensureLogger(logger),
		metrics:           metrics,
	}
}

// hashOTP returns the hex HMAC-SHA256 of an OTP code under the configured secret.
// OTP codes are stored and compared only as this keyed hash, so a read-only
// database/backup/replica disclosure does not expose usable codes — mirroring how
// refresh tokens and API keys are stored. The keyspace of a 6-digit code is tiny,
// so a *keyed* HMAC (server secret never in the DB) is what provides the
// protection; an unkeyed hash would be trivially brute-forced.
func (s *OTPService) hashOTP(code string) string {
	h := hmac.New(sha256.New, []byte(s.hmacSecret))
	h.Write([]byte(code))
	return hex.EncodeToString(h.Sum(nil))
}

// Generate creates a new OTP or replaces an existing one (upsert behavior)
// with rate limiting to prevent spam/abuse
//
// Rate Limiting:
//   - Checks if an OTP was created within the rate limit window
//   - Returns error if rate limit is violated
//   - Configurable rate limit duration (default: 1 minute)
//
// Note: One OTP per (tenant, email, purpose) at any time; generating a new one
// for the same key replaces it and resets its failed-attempt counter.
//
// Returns:
//   - Generated 6-digit OTP code (plaintext, for email sending)
//   - Expiration timestamp
//   - Error if rate limit violated or database error
func (s *OTPService) Generate(ctx context.Context, req model.OTPGenerateRequest) (*model.GenerateResponse, error) {
	tenantID, purpose, expirationDuration := req.TenantID, req.Purpose, req.ExpirationDuration
	email := normalizeEmail(req.Email)

	// OTP codes are stored as a keyed HMAC, so the secret is mandatory. Fail with a
	// matchable sentinel (analogous to SecretService) rather than silently hashing
	// with an empty key.
	if s.hmacSecret == "" {
		return nil, model.ErrOTPSecretMissing
	}

	// Reject a non-positive expiration up front. A zero (the zero value, so an
	// omitted field) or negative duration would mint a code that is already expired
	// the instant it is issued — it can never be validated, yet the caller would
	// still receive a success response and consume the rate-limit window. Surface it
	// as a clear caller error instead, mirroring CreateAPIKey's positive-duration check.
	if expirationDuration <= 0 {
		return nil, fmt.Errorf("otp expiration duration must be positive (got %s)", expirationDuration)
	}

	// Check rate limiting: read the current OTP (from the primary, so replication
	// lag cannot let a just-issued code slip past the limit) to inspect its
	// created_at. A missing code (ErrNotFound) means none is active, which is
	// fine; any other error is a hard failure — failing open here would silently
	// disable the rate limit on a transient DB error.
	existingOTP, err := s.repo.GetVerificationCode(ctx, tenantID, email, purpose)
	if err != nil && !errors.Is(err, model.ErrNotFound) {
		s.logger.Error("failed to read OTP for rate limiting",
			"email", maskEmail(email),
			"purpose", purpose,
			"error", err.Error(),
		)
		return nil, sanitizeError(s.logger, "check otp rate limit", err)
	}

	// Enforce rate limiting if OTP exists and was created recently
	if existingOTP != nil {
		timeSinceCreation := time.Since(existingOTP.CreatedAt)
		if timeSinceCreation < s.rateLimitDuration {
			remainingTime := s.rateLimitDuration - timeSinceCreation
			s.logger.Warn("OTP generation rate limit exceeded",
				"email", maskEmail(email),
				"purpose", purpose,
				"time_since_creation", timeSinceCreation,
				"rate_limit", s.rateLimitDuration,
				"remaining_time", remainingTime,
			)
			return nil, fmt.Errorf("please wait %v before requesting a new OTP: %w", remainingTime.Round(time.Second), model.ErrOTPRateLimited)
		}
	}

	// Generate 6-digit OTP code using crypto/rand for security
	code, err := generateSecureOTP(6)
	if err != nil {
		s.logger.Error("failed to generate secure OTP code",
			"email", maskEmail(email),
			"purpose", purpose,
			"error", err.Error(),
		)
		return nil, sanitizeError(s.logger, "generate otp", err)
	}

	// Calculate expiration timestamp
	expiresAt := time.Now().Add(expirationDuration)

	// Upsert OTP to database (create or replace). Only the keyed HMAC of the code is
	// persisted; the plaintext is returned to the caller (below) for delivery and is
	// never stored.
	upsertReq := repository.CreateVerificationCodeRequest{
		TenantID:  tenantID,
		Email:     email,
		CodeHash:  s.hashOTP(code),
		Purpose:   purpose,
		ExpiresAt: expiresAt,
	}

	// Authoritative, race-free rate-limit enforcement: the upsert only replaces an
	// existing code older than rateLimitDuration. stored == false means a more
	// recent code already exists (a concurrent request won the race past the
	// fast-path check above), so report rate-limited rather than overwriting it.
	stored, err := s.repo.UpsertVerificationCode(ctx, upsertReq, s.rateLimitDuration)
	if err != nil {
		s.logger.Error("failed to store OTP in database",
			"email", maskEmail(email),
			"purpose", purpose,
			"error", err.Error(),
		)
		return nil, sanitizeError(s.logger, "store otp", err)
	}
	if !stored {
		s.logger.Warn("OTP generation rate limit exceeded (atomic guard)",
			"email", maskEmail(email),
			"purpose", purpose,
		)
		return nil, fmt.Errorf("please wait before requesting a new OTP: %w", model.ErrOTPRateLimited)
	}

	s.logger.Info("OTP generated successfully",
		"email", maskEmail(email),
		"purpose", purpose,
		"expires_at", expiresAt,
		"expiration_duration", expirationDuration,
	)

	return &model.GenerateResponse{
		Code:      code,
		ExpiresAt: expiresAt,
	}, nil
}

// Validate verifies an OTP code and deletes it on success (single-use enforcement)
//
// Validation Checks:
//   - OTP exists for the given email
//   - OTP has not expired
//   - Provided code matches stored code
//   - Purpose matches
//
// Single-Use Enforcement:
//   - OTP is deleted atomically while validating it
//   - Subsequent validation attempts with the same code will fail
//
// Brute-force Protection:
//   - Each failed attempt against an issued code is counted; after
//     MaxOTPValidationAttempts failures the code is invalidated and the caller
//     must request a new one. This bounds online guessing of the short code.
//
// Note: Codes are scoped to (tenant, email, purpose).
//
// Returns:
//   - nil if OTP is valid (and deletes it)
//   - error if OTP is invalid, expired, not found, or locked out after too many attempts
func (s *OTPService) Validate(ctx context.Context, req model.OTPValidateRequest) error {
	tenantID, code, purpose := req.TenantID, req.Code, req.Purpose
	email := normalizeEmail(req.Email)

	if s.hmacSecret == "" {
		return model.ErrOTPSecretMissing
	}

	// Hash the supplied code under the same secret used at generation; the stored
	// value is the HMAC, so the repository compares hash-to-hash (constant-time).
	result, err := s.repo.ConsumeVerificationCode(ctx, tenantID, email, s.hashOTP(code), purpose, MaxOTPValidationAttempts)
	if err != nil {
		s.logger.Error("OTP validation failed",
			"tenant_id", tenantID,
			"email", maskEmail(email),
			"purpose", purpose,
			"error", err.Error(),
		)
		return sanitizeError(s.logger, "validate otp", err)
	}

	switch result {
	case repository.OTPConsumeValid:
		s.logger.Info("OTP validated successfully",
			"tenant_id", tenantID,
			"email", maskEmail(email),
			"purpose", purpose,
		)
		return nil
	case repository.OTPConsumeLockedOut:
		s.logger.Warn("OTP locked out after too many failed attempts",
			"tenant_id", tenantID,
			"email", maskEmail(email),
			"purpose", purpose,
		)
		incMetric(s.metrics, metrics.CounterOTPLockout)
		return fmt.Errorf("too many invalid attempts; request a new OTP: %w", model.ErrOTPLockedOut)
	default: // repository.OTPConsumeInvalid
		s.logger.Warn("OTP validation failed",
			"tenant_id", tenantID,
			"email", maskEmail(email),
			"purpose", purpose,
		)
		incMetric(s.metrics, metrics.CounterOTPFailure)
		return fmt.Errorf("invalid or expired OTP: %w", model.ErrInvalidOTP)
	}
}

// Delete explicitly revokes an OTP before it's used
// Use cases: User cancels operation, admin revokes pending OTP
//
// Note: Deletes the OTP for the specific (tenant, email, purpose)
func (s *OTPService) Delete(ctx context.Context, tenantID, email, purpose string) error {
	email = normalizeEmail(email)
	err := s.repo.DeleteVerificationCode(ctx, tenantID, email, purpose)
	if err != nil {
		s.logger.Error("failed to delete OTP",
			"email", maskEmail(email),
			"purpose", purpose,
			"error", err.Error(),
		)
		return sanitizeError(s.logger, "delete otp", err)
	}

	s.logger.Info("OTP deleted successfully",
		"email", maskEmail(email),
		"purpose", purpose,
	)

	return nil
}

// CleanupExpired removes all expired OTP codes from the database
// Should be called periodically as a maintenance job (e.g., hourly cron)
//
// Returns:
//   - Number of expired OTPs deleted
//   - Error if database operation fails
func (s *OTPService) CleanupExpired(ctx context.Context) (int64, error) {
	deletedCount, err := s.repo.DeleteExpiredVerificationCodes(ctx)
	if err != nil {
		s.logger.Error("failed to cleanup expired OTPs",
			"error", err.Error(),
		)
		return 0, sanitizeError(s.logger, "cleanup expired otps", err)
	}

	s.logger.Info("expired OTPs cleaned up successfully",
		"deleted_count", deletedCount,
	)

	return deletedCount, nil
}

// generateSecureOTP generates a cryptographically secure random numeric OTP
// Uses crypto/rand for security (not math/rand which is predictable)
func generateSecureOTP(length int) (string, error) {
	if length <= 0 {
		return "", errors.New("OTP length must be positive")
	}

	// Generate random digits using crypto/rand
	const digits = "0123456789"
	result := make([]byte, length)

	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %w", err)
		}
		result[i] = digits[num.Int64()]
	}

	return string(result), nil
}
