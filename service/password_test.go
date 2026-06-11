// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
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
}
