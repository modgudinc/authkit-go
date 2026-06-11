// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import "strings"

// normalizeEmail canonicalizes an email address for storage and lookup by
// trimming surrounding whitespace and lowercasing it. Applying this consistently
// at every entry point ensures "User@Acme.com" and "user@acme.com " resolve to
// the same account and OTP key, and matches the normalization the invitation
// flow already performs.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
