// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"
	"time"
)

func TestUserHasPassword(t *testing.T) {
	if (&User{}).HasPassword() {
		t.Fatal("a user with an empty hash has no password")
	}
	if !(&User{PasswordHash: "$2a$04$hash"}).HasPassword() {
		t.Fatal("a user with a hash has a password")
	}
}

func TestUserHasVerifiedEmail(t *testing.T) {
	if (&User{}).HasVerifiedEmail() {
		t.Fatal("a user without EmailVerifiedAt is unverified")
	}
	now := time.Now()
	if !(&User{EmailVerifiedAt: &now}).HasVerifiedEmail() {
		t.Fatal("a user with EmailVerifiedAt is verified")
	}
}
