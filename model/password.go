// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

// PasswordStrengthRequirements defines the minimum password requirements
type PasswordStrengthRequirements struct {
	MinLength      int  // Minimum password length in bytes (default: 8)
	MaxLength      int  // Maximum password length in bytes (default: 72; 0 means the bcrypt cap)
	RequireUpper   bool // Require at least one uppercase letter
	RequireLower   bool // Require at least one lowercase letter
	RequireNumber  bool // Require at least one digit
	RequireSpecial bool // Require at least one special character
}

// DefaultPasswordRequirements returns sensible default password requirements.
//
// MaxLength defaults to 72 bytes: bcrypt only considers the first 72 bytes of a
// password (golang.org/x/crypto rejects longer input outright), so enforcing the
// cap here turns an otherwise opaque hashing failure into a clear validation
// error.
func DefaultPasswordRequirements() PasswordStrengthRequirements {
	return PasswordStrengthRequirements{
		MinLength:      8,
		MaxLength:      72,
		RequireUpper:   true,
		RequireLower:   true,
		RequireNumber:  true,
		RequireSpecial: true,
	}
}
