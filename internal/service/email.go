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

// isValidEmail reports whether email is a syntactically valid address: a non-empty
// local part with no whitespace, a single "@", and a domain matching domainRegex
// (defined in tenant.go). It is a conservative structural check (not full RFC 5322)
// — enough to reject empty or obviously malformed targets at the library boundary.
// Callers should normalizeEmail first.
func isValidEmail(email string) bool {
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return false
	}
	local, domain := email[:at], email[at+1:]
	if strings.ContainsAny(local, "@ \t\r\n") {
		return false
	}
	return domainRegex.MatchString(domain)
}

// maskEmail redacts an email address for logging. Logs are treated as a hostile
// surface (see SECURITY.md), so we never emit the full address; instead we keep
// the first character of the local part and the full domain (e.g.
// "user@acme.com" -> "u***@acme.com"), which is enough to correlate log entries
// during an investigation without recording the plaintext PII. Inputs without a
// usable local part are fully redacted.
func maskEmail(email string) string {
	at := strings.IndexByte(email, '@')
	if at <= 0 {
		return "***"
	}
	return email[:1] + "***" + email[at:]
}
