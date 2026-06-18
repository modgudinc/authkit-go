// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode"

	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/model"
	"golang.org/x/crypto/bcrypt"
)

// DefaultBcryptCost is the default cost factor for bcrypt hashing
// Cost of 12 provides a good balance between security and performance
const DefaultBcryptCost = 12

// bcryptMaxPasswordBytes is the maximum input length bcrypt considers. The
// golang.org/x/crypto implementation rejects passwords longer than this rather
// than silently truncating, so it doubles as the hard upper bound on password
// length regardless of the configured MaxLength.
const bcryptMaxPasswordBytes = 72

// PasswordService handles password hashing and verification using bcrypt
type PasswordService struct {
	cost   int
	logger logger.Logger

	// dummyHash is a bcrypt hash computed lazily at the configured cost, used by
	// DummyVerify to equalize timing on paths that would otherwise skip a real
	// password comparison (e.g. unknown user), preventing username enumeration.
	// Guarded by dummyMu; computed on first use and re-attempted on a later call if
	// a prior generation failed, rather than latching the failure (which would
	// silently disable the timing equalizer for the process lifetime).
	dummyMu   sync.Mutex
	dummyHash string
}

// NewPasswordService creates a new PasswordService instance
//
// Parameters:
//   - cost: bcrypt cost factor (4-31, recommended: 12)
//   - logger: optional logger for structured logging
//
// If cost is 0 or invalid, DefaultBcryptCost (12) is used
func NewPasswordService(cost int, logger logger.Logger) *PasswordService {
	// Validate and set cost
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = DefaultBcryptCost
	}

	return &PasswordService{
		cost:   cost,
		logger: ensureLogger(logger),
	}
}

// HashPassword hashes a plaintext password using bcrypt
//
// Parameters:
//   - password: plaintext password to hash
//
// # Returns the bcrypt hash string or an error if hashing fails
//
// Example:
//
//	hash, err := passwordService.HashPassword("SecurePassword123!")
//	if err != nil {
//	    return fmt.Errorf("failed to hash password: %w", err)
//	}
//	// Store hash in database
func (s *PasswordService) HashPassword(password string) (string, error) {
	s.logger.Info("Hashing password", "cost", s.cost)

	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cost)
	if err != nil {
		s.logger.Error("Failed to hash password", "error", err.Error())
		// A password over bcrypt's 72-byte limit is a caller input problem, not an
		// internal fault; surface it as the matchable strength sentinel so callers
		// that bypass ValidatePasswordStrength still get a clean classification.
		if errors.Is(err, bcrypt.ErrPasswordTooLong) {
			return "", fmt.Errorf("password exceeds %d bytes: %w", bcryptMaxPasswordBytes, model.ErrPasswordTooWeak)
		}
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hash), nil
}

// VerifyPassword verifies a plaintext password against a bcrypt hash
//
// Parameters:
//   - password: plaintext password to verify
//   - hash: bcrypt hash to compare against
//
// Returns nil if the password matches, error otherwise.
// bcrypt is a slow adaptive hash and its comparison does not short-circuit on
// content, so verification time does not leak how much of the password matched.
//
// Example:
//
//	err := passwordService.VerifyPassword("userInput", storedHash)
//	if err != nil {
//	    // Password is incorrect
//	    return fmt.Errorf("invalid password")
//	}
//	// Password is correct, proceed with authentication
func (s *PasswordService) VerifyPassword(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			s.logger.Warn("Password verification failed: incorrect password")
			return fmt.Errorf("incorrect password")
		}

		s.logger.Error("Password verification error", "error", err.Error())
		return fmt.Errorf("password verification failed: %w", err)
	}

	s.logger.Info("Password verified successfully")

	return nil
}

// DummyVerify performs a throwaway bcrypt comparison against an internal dummy
// hash (generated once at the configured cost). It does no useful work — its sole
// purpose is to make code paths that have no real hash to check (e.g. a login
// attempt for an email that does not exist, or a disabled/locked account that is
// rejected before password verification) take about as long as a genuine
// VerifyPassword call. This closes the timing side channel that would otherwise
// let an attacker enumerate valid accounts. The result is intentionally ignored.
func (s *PasswordService) DummyVerify(password string) {
	if hash := s.dummyVerifyHash(); hash != "" {
		_ = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	}
}

// dummyVerifySeed is the fixed input hashed to produce the throwaway hash that
// DummyVerify compares against. Its value is irrelevant (it is never a real
// credential) — only that hashing it yields a valid bcrypt hash at the configured cost.
const dummyVerifySeed = "authkit-dummy-verify-seed-for-constant-time"

// dummyVerifyHash returns the cached dummy bcrypt hash, generating it on first use.
// Unlike sync.Once, it re-attempts generation on a later call if a prior attempt
// failed, so a (near-impossible, but defensive) transient failure cannot
// permanently disable DummyVerify's timing equalization. Returns "" only while
// generation is still failing.
func (s *PasswordService) dummyVerifyHash() string {
	s.dummyMu.Lock()
	defer s.dummyMu.Unlock()
	if s.dummyHash == "" {
		h, err := bcrypt.GenerateFromPassword([]byte(dummyVerifySeed), s.cost)
		if err != nil {
			s.logger.Error("failed to generate dummy bcrypt hash for timing equalization", "error", err.Error())
			return ""
		}
		s.dummyHash = string(h)
	}
	return s.dummyHash
}

// ValidatePasswordStrength validates password strength against requirements
//
// Parameters:
//   - password: plaintext password to validate
//   - requirements: password strength requirements
//
// # Returns nil if password meets requirements, error with details otherwise
//
// Example:
//
//	err := passwordService.ValidatePasswordStrength("weak", model.DefaultPasswordRequirements())
//	if err != nil {
//	    // Return validation error to user
//	    return fmt.Errorf("password validation failed: %w", err)
//	}
func (s *PasswordService) ValidatePasswordStrength(password string, requirements model.PasswordStrengthRequirements) error {
	var problems []string

	// Check minimum length
	if len(password) < requirements.MinLength {
		problems = append(problems, fmt.Sprintf("must be at least %d characters", requirements.MinLength))
	}

	// Check maximum length. bcrypt only hashes the first 72 bytes and rejects
	// longer input, so cap at bcryptMaxPasswordBytes even when MaxLength is unset
	// (0) or configured higher.
	maxLength := requirements.MaxLength
	if maxLength <= 0 || maxLength > bcryptMaxPasswordBytes {
		maxLength = bcryptMaxPasswordBytes
	}
	if len(password) > maxLength {
		problems = append(problems, fmt.Sprintf("must be at most %d bytes", maxLength))
	}

	// Check for uppercase letter
	if requirements.RequireUpper && !hasUppercase(password) {
		problems = append(problems, "must contain at least one uppercase letter")
	}

	// Check for lowercase letter
	if requirements.RequireLower && !hasLowercase(password) {
		problems = append(problems, "must contain at least one lowercase letter")
	}

	// Check for digit
	if requirements.RequireNumber && !hasDigit(password) {
		problems = append(problems, "must contain at least one digit")
	}

	// Check for special character
	if requirements.RequireSpecial && !hasSpecial(password) {
		problems = append(problems, "must contain at least one special character")
	}

	if len(problems) > 0 {
		s.logger.Warn("Password strength validation failed", "errors", problems)
		return fmt.Errorf("password %s: %w", strings.Join(problems, "; "), model.ErrPasswordTooWeak)
	}

	s.logger.Info("Password meets strength requirements")

	return nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// hasUppercase checks if string contains at least one uppercase letter
func hasUppercase(s string) bool {
	for _, ch := range s {
		if unicode.IsUpper(ch) {
			return true
		}
	}
	return false
}

// hasLowercase checks if string contains at least one lowercase letter
func hasLowercase(s string) bool {
	for _, ch := range s {
		if unicode.IsLower(ch) {
			return true
		}
	}
	return false
}

// hasDigit checks if string contains at least one digit
func hasDigit(s string) bool {
	for _, ch := range s {
		if unicode.IsDigit(ch) {
			return true
		}
	}
	return false
}

// hasSpecial checks if string contains at least one special character
func hasSpecial(s string) bool {
	for _, ch := range s {
		if unicode.IsPunct(ch) || unicode.IsSymbol(ch) {
			return true
		}
	}
	return false
}
