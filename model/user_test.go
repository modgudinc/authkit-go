// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "testing"

func TestUserHasPassword(t *testing.T) {
	if (&User{}).HasPassword() {
		t.Fatal("a user with an empty hash has no password")
	}
	if !(&User{PasswordHash: "$2a$04$hash"}).HasPassword() {
		t.Fatal("a user with a hash has a password")
	}
}
