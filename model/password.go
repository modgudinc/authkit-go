// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

// PasswordStrengthRequirements defines the minimum password requirements
type PasswordStrengthRequirements struct {
	MinLength      int  // Minimum password length (default: 8)
	RequireUpper   bool // Require at least one uppercase letter
	RequireLower   bool // Require at least one lowercase letter
	RequireNumber  bool // Require at least one digit
	RequireSpecial bool // Require at least one special character
}

// DefaultPasswordRequirements returns sensible default password requirements
func DefaultPasswordRequirements() PasswordStrengthRequirements {
	return PasswordStrengthRequirements{
		MinLength:      8,
		RequireUpper:   true,
		RequireLower:   true,
		RequireNumber:  true,
		RequireSpecial: true,
	}
}
