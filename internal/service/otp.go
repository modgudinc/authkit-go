// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/logger"
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
	logger            logger.Logger
}

type otpRepository interface {
	GetVerificationCode(ctx context.Context, tenantID, email, purpose string) (*repository.VerificationCode, error)
	UpsertVerificationCode(ctx context.Context, req repository.CreateVerificationCodeRequest, rateLimit time.Duration) (bool, error)
	ConsumeVerificationCode(ctx context.Context, tenantID, email, code, purpose string, maxAttempts int) (repository.OTPConsumeResult, error)
	DeleteVerificationCode(ctx context.Context, tenantID, email, purpose string) error
	DeleteExpiredVerificationCodes(ctx context.Context) (int64, error)
}

// NewOTPService creates a new OTP service instance
func NewOTPService(repo *repository.Repository, rateLimitDuration time.Duration, logger logger.Logger) *OTPService {
	return &OTPService{
		repo:              repo,
		rateLimitDuration: rateLimitDuration,
		logger:            logger,
	}
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

	// Check rate limiting: read the current OTP (from the primary, so replication
	// lag cannot let a just-issued code slip past the limit) to inspect its
	// created_at. A missing code (ErrNotFound) means none is active, which is
	// fine; any other error is a hard failure — failing open here would silently
	// disable the rate limit on a transient DB error.
	existingOTP, err := s.repo.GetVerificationCode(ctx, tenantID, email, purpose)
	if err != nil && !errors.Is(err, model.ErrNotFound) {
		if s.logger != nil {
			s.logger.Error("failed to read OTP for rate limiting",
				"email", maskEmail(email),
				"purpose", purpose,
				"error", err,
			)
		}
		return nil, sanitizeError(nil, "check otp rate limit", err)
	}

	// Enforce rate limiting if OTP exists and was created recently
	if existingOTP != nil {
		timeSinceCreation := time.Since(existingOTP.CreatedAt)
		if timeSinceCreation < s.rateLimitDuration {
			remainingTime := s.rateLimitDuration - timeSinceCreation
			if s.logger != nil {
				s.logger.Warn("OTP generation rate limit exceeded",
					"email", maskEmail(email),
					"purpose", purpose,
					"time_since_creation", timeSinceCreation,
					"rate_limit", s.rateLimitDuration,
					"remaining_time", remainingTime,
				)
			}
			return nil, fmt.Errorf("please wait %v before requesting a new OTP: %w", remainingTime.Round(time.Second), model.ErrOTPRateLimited)
		}
	}

	// Generate 6-digit OTP code using crypto/rand for security
	code, err := generateSecureOTP(6)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to generate secure OTP code",
				"email", maskEmail(email),
				"purpose", purpose,
				"error", err,
			)
		}
		return nil, sanitizeError(nil, "generate otp", err)
	}

	// Calculate expiration timestamp
	expiresAt := time.Now().Add(expirationDuration)

	// Upsert OTP to database (create or replace)
	upsertReq := repository.CreateVerificationCodeRequest{
		TenantID:  tenantID,
		Email:     email,
		Code:      code,
		Purpose:   purpose,
		ExpiresAt: expiresAt,
	}

	// Authoritative, race-free rate-limit enforcement: the upsert only replaces an
	// existing code older than rateLimitDuration. stored == false means a more
	// recent code already exists (a concurrent request won the race past the
	// fast-path check above), so report rate-limited rather than overwriting it.
	stored, err := s.repo.UpsertVerificationCode(ctx, upsertReq, s.rateLimitDuration)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to store OTP in database",
				"email", maskEmail(email),
				"purpose", purpose,
				"error", err,
			)
		}
		return nil, sanitizeError(nil, "store otp", err)
	}
	if !stored {
		if s.logger != nil {
			s.logger.Warn("OTP generation rate limit exceeded (atomic guard)",
				"email", maskEmail(email),
				"purpose", purpose,
			)
		}
		return nil, fmt.Errorf("please wait before requesting a new OTP: %w", model.ErrOTPRateLimited)
	}

	if s.logger != nil {
		s.logger.Info("OTP generated successfully",
			"email", maskEmail(email),
			"purpose", purpose,
			"expires_at", expiresAt,
			"expiration_duration", expirationDuration,
		)
	}

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
	result, err := s.repo.ConsumeVerificationCode(ctx, tenantID, email, code, purpose, MaxOTPValidationAttempts)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("OTP validation failed",
				"tenant_id", tenantID,
				"email", maskEmail(email),
				"purpose", purpose,
				"error", err,
			)
		}
		return sanitizeError(nil, "validate otp", err)
	}

	switch result {
	case repository.OTPConsumeValid:
		if s.logger != nil {
			s.logger.Info("OTP validated successfully",
				"tenant_id", tenantID,
				"email", maskEmail(email),
				"purpose", purpose,
			)
		}
		return nil
	case repository.OTPConsumeLockedOut:
		if s.logger != nil {
			s.logger.Warn("OTP locked out after too many failed attempts",
				"tenant_id", tenantID,
				"email", maskEmail(email),
				"purpose", purpose,
			)
		}
		return fmt.Errorf("too many invalid attempts; request a new OTP: %w", model.ErrOTPLockedOut)
	default: // repository.OTPConsumeInvalid
		if s.logger != nil {
			s.logger.Warn("OTP validation failed",
				"tenant_id", tenantID,
				"email", maskEmail(email),
				"purpose", purpose,
			)
		}
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
		if s.logger != nil {
			s.logger.Error("failed to delete OTP",
				"email", maskEmail(email),
				"purpose", purpose,
				"error", err,
			)
		}
		return sanitizeError(nil, "delete otp", err)
	}

	if s.logger != nil {
		s.logger.Info("OTP deleted successfully",
			"email", maskEmail(email),
			"purpose", purpose,
		)
	}

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
		if s.logger != nil {
			s.logger.Error("failed to cleanup expired OTPs",
				"error", err,
			)
		}
		return 0, sanitizeError(nil, "cleanup expired otps", err)
	}

	if s.logger != nil {
		s.logger.Info("expired OTPs cleaned up successfully",
			"deleted_count", deletedCount,
		)
	}

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
