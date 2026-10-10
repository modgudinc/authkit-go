// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 TOTP is defined over HMAC-SHA1, which authenticator apps use
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters (RFC 6238 as authenticator apps implement it): HMAC-SHA1,
// 6 digits, 30-second steps. A code is accepted for its own step and the steps
// either side, to allow for clock drift and typing time.
const (
	totpSecretBytes = 20
	totpDigits      = 6
	totpPeriod      = 30 // seconds
	totpSkewSteps   = 1
)

// totpEncoding is base32 without padding, as otpauth URIs and authenticator apps
// expect.
var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// totpStep is the 30-second step t falls in.
func totpStep(t time.Time) int64 {
	return t.Unix() / totpPeriod
}

// totpCode is the code for secret at step (RFC 4226 HOTP with the step as counter).
func totpCode(secret []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step)) // #nosec G115 -- steps since 1970 are positive
	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, value%1000000)
}

// matchTOTP returns the step whose code is code, among the steps around now, and
// whether one matched. It compares every candidate in constant time.
func matchTOTP(secret []byte, code string, now time.Time) (int64, bool) {
	current := totpStep(now)
	var matched int64
	found := 0
	for step := current - totpSkewSteps; step <= current+totpSkewSteps; step++ {
		if subtle.ConstantTimeCompare([]byte(totpCode(secret, step)), []byte(code)) == 1 {
			matched, found = step, 1
		}
	}
	return matched, found == 1
}

// isTOTPCode reports whether code looks like an authenticator-app code (6 digits)
// rather than a recovery code.
func isTOTPCode(code string) bool {
	if len(code) != totpDigits {
		return false
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// totpURI is the otpauth:// URI for a secret, labelled issuer:account, that
// authenticator apps read from a QR code.
func totpURI(issuer, account string, secret []byte) string {
	q := url.Values{}
	q.Set("secret", totpEncoding.EncodeToString(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	return "otpauth://totp/" + label + "?" + strings.ReplaceAll(q.Encode(), "+", "%20")
}
