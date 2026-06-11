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

// PasswordService handles password hashing and verification using bcrypt
type PasswordService struct {
	cost   int
	logger logger.Logger

	// dummyHash is a bcrypt hash computed lazily at the configured cost, used by
	// DummyVerify to equalize timing on paths that would otherwise skip a real
	// password comparison (e.g. unknown user), preventing username enumeration.
	dummyOnce sync.Once
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
		logger: logger,
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
	if s.logger != nil {
		s.logger.Info("Hashing password", "cost", s.cost)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cost)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to hash password", "error", err.Error())
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
// Returns nil if the password matches, error otherwise
// Uses constant-time comparison to prevent timing attacks
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
			if s.logger != nil {
				s.logger.Warn("Password verification failed: incorrect password")
			}
			return fmt.Errorf("incorrect password")
		}

		if s.logger != nil {
			s.logger.Error("Password verification error", "error", err.Error())
		}
		return fmt.Errorf("password verification failed: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("Password verified successfully")
	}

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
	s.dummyOnce.Do(func() {
		h, err := bcrypt.GenerateFromPassword([]byte("authkit-dummy-password-for-constant-time"), s.cost)
		if err == nil {
			s.dummyHash = string(h)
		}
	})
	if s.dummyHash != "" {
		_ = bcrypt.CompareHashAndPassword([]byte(s.dummyHash), []byte(password))
	}
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
	var errors []string

	// Check minimum length
	if len(password) < requirements.MinLength {
		errors = append(errors, fmt.Sprintf("must be at least %d characters", requirements.MinLength))
	}

	// Check for uppercase letter
	if requirements.RequireUpper && !hasUppercase(password) {
		errors = append(errors, "must contain at least one uppercase letter")
	}

	// Check for lowercase letter
	if requirements.RequireLower && !hasLowercase(password) {
		errors = append(errors, "must contain at least one lowercase letter")
	}

	// Check for digit
	if requirements.RequireNumber && !hasDigit(password) {
		errors = append(errors, "must contain at least one digit")
	}

	// Check for special character
	if requirements.RequireSpecial && !hasSpecial(password) {
		errors = append(errors, "must contain at least one special character")
	}

	if len(errors) > 0 {
		if s.logger != nil {
			s.logger.Warn("Password strength validation failed", "errors", errors)
		}
		return fmt.Errorf("password validation failed: %s", strings.Join(errors, "; "))
	}

	if s.logger != nil {
		s.logger.Info("Password meets strength requirements")
	}

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
