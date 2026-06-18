// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/modgudinc/authkit-go/model"
	"golang.org/x/crypto/bcrypt"
)

func TestPasswordServiceHashAndVerify(t *testing.T) {
	service := NewPasswordService(bcrypt.MinCost, nil)

	hash, err := service.HashPassword("CorrectHorseBatteryStaple1!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if hash == "CorrectHorseBatteryStaple1!" {
		t.Fatal("hash should not equal plaintext password")
	}

	if err := service.VerifyPassword("CorrectHorseBatteryStaple1!", hash); err != nil {
		t.Fatalf("verify password: %v", err)
	}
	if err := service.VerifyPassword("wrong-password", hash); err == nil {
		t.Fatal("expected wrong password to fail")
	}
}

func TestPasswordServiceDefaultsInvalidCost(t *testing.T) {
	service := NewPasswordService(0, nil)

	if service.cost != DefaultBcryptCost {
		t.Fatalf("cost = %d, want %d", service.cost, DefaultBcryptCost)
	}
}

func TestPasswordStrengthValidation(t *testing.T) {
	service := NewPasswordService(bcrypt.MinCost, nil)
	requirements := model.PasswordStrengthRequirements{
		MinLength:      8,
		RequireUpper:   true,
		RequireLower:   true,
		RequireNumber:  true,
		RequireSpecial: true,
	}

	if err := service.ValidatePasswordStrength("ValidPass1!", requirements); err != nil {
		t.Fatalf("expected password to pass: %v", err)
	}

	err := service.ValidatePasswordStrength("weak", requirements)
	if err == nil {
		t.Fatal("expected weak password to fail")
	}
	for _, want := range []string{"at least 8", "uppercase", "digit", "special"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error to contain %q, got %q", want, err.Error())
		}
	}
	// A strength failure must be matchable with errors.Is so callers can map it to
	// a 400 instead of treating it as an opaque internal error.
	if !errors.Is(err, model.ErrPasswordTooWeak) {
		t.Fatalf("expected weak-password error to wrap ErrPasswordTooWeak, got %v", err)
	}
}

// TestPasswordStrengthRejectsOverLong verifies the bcrypt 72-byte cap is enforced
// as a clean strength failure (default requirements) rather than surfacing later
// as an opaque hashing error.
func TestPasswordStrengthRejectsOverLong(t *testing.T) {
	service := NewPasswordService(bcrypt.MinCost, nil)

	long := strings.Repeat("A1a!", 20) // 80 bytes > 72
	err := service.ValidatePasswordStrength(long, model.DefaultPasswordRequirements())
	if err == nil {
		t.Fatal("expected an over-72-byte password to fail validation")
	}
	if !errors.Is(err, model.ErrPasswordTooWeak) {
		t.Fatalf("expected over-long error to wrap ErrPasswordTooWeak, got %v", err)
	}
}

// TestHashPasswordOverLongReturnsSentinel verifies callers that bypass
// ValidatePasswordStrength (e.g. the invitation flow) still get a matchable
// ErrPasswordTooWeak instead of a generic "failed to hash password" error.
func TestHashPasswordOverLongReturnsSentinel(t *testing.T) {
	service := NewPasswordService(bcrypt.MinCost, nil)

	if _, err := service.HashPassword(strings.Repeat("x", 100)); !errors.Is(err, model.ErrPasswordTooWeak) {
		t.Fatalf("expected over-long HashPassword to wrap ErrPasswordTooWeak, got %v", err)
	}
}

// TestDummyVerifyRunsBcryptCompare asserts that DummyVerify lazily builds a real
// bcrypt hash and runs a comparison against it, so the login timing-equalization
// on the user-absent / disabled / locked paths cannot be silently dropped by a
// future refactor.
func TestDummyVerifyRunsBcryptCompare(t *testing.T) {
	s := NewPasswordService(bcrypt.MinCost, nil)
	if s.dummyHash != "" {
		t.Fatal("dummy hash should be lazily initialized, not set at construction")
	}

	s.DummyVerify("anything")

	if s.dummyHash == "" {
		t.Fatal("expected DummyVerify to populate the dummy hash (bcrypt work ran)")
	}
	// The populated value must be a real bcrypt hash (a genuine compare happened).
	if _, err := bcrypt.Cost([]byte(s.dummyHash)); err != nil {
		t.Fatalf("dummy hash is not a valid bcrypt hash: %v", err)
	}
}

// TestDummyVerifyHashIsStableAcrossCalls asserts the dummy hash is generated once
// and then reused, so DummyVerify does not pay a fresh bcrypt generation on every
// call (it should be a single compare after the first use).
func TestDummyVerifyHashIsStableAcrossCalls(t *testing.T) {
	s := NewPasswordService(bcrypt.MinCost, nil)

	s.DummyVerify("a")
	first := s.dummyHash
	if first == "" {
		t.Fatal("expected dummy hash to be computed on first use")
	}

	s.DummyVerify("b")
	if s.dummyHash != first {
		t.Fatal("dummy hash should be reused across calls, not regenerated")
	}
}
