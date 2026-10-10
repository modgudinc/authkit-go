//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP is defined over HMAC-SHA1
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	authkit "github.com/modgudinc/authkit-go"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
)

// twoFactorKey is a fixed test key: base64 of 32 bytes.
const twoFactorKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

// twoFactorKit is historyKit with two-factor configured (when on) and sign-ins
// recorded.
func twoFactorKit(t *testing.T, db *sql.DB, mode authkit.SessionMode, on bool, m metrics.Metrics) *authkit.AuthKit {
	t.Helper()
	namespace := ""
	if mode != authkit.SessionDisabled {
		namespace = "app"
	}
	config := authkit.Config{
		DBConnection: authkit.DatabaseConnection{IdentityRWDB: db, IdentityRODB: db},
		JWTConfig: authkit.JWTConfig{
			AccessSecret:           "integration-access-secret-at-least-32-bytes",
			RefreshTokenHMACSecret: "integration-refresh-hmac-secret-at-least-32b",
			AccessExpiry:           5 * time.Minute, RefreshExpiry: time.Hour,
		},
		APIKeyConfig:   authkit.APIKeyConfig{HMACSecret: "integration-api-hmac-secret-at-least-32-bytes"},
		PasswordConfig: authkit.PasswordConfig{BcryptCost: 4},
		SessionConfig:  authkit.SessionConfig{Mode: mode, Namespace: namespace, AbsoluteLifetime: 2 * time.Hour},
		Metrics:        m,
		RecordSignIns:  true,
	}
	if on {
		config.TwoFactorConfig = authkit.TwoFactorConfig{EncryptionKey: twoFactorKey, Issuer: "Acme Corp"}
	}
	k, err := authkit.New(config)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// twoFactorFixture is historyFixture with the two-factor migration applied and a
// kit with two-factor on.
func twoFactorFixture(t *testing.T, mode authkit.SessionMode) (*sql.DB, *authkit.AuthKit, *countingMetrics, string) {
	t.Helper()
	db, _, userID := historyFixture(t, mode, true)
	db.SetMaxOpenConns(12)
	applyMigration(t, db, "000009_two_factor.up.sql")
	m := &countingMetrics{}
	return db, twoFactorKit(t, db, mode, true, m), m, userID
}

// totpAt is what an authenticator app shows for the base32 secret at step. It is
// written here from RFC 6238, apart from authkit's own.
func totpAt(t *testing.T, secret string, step int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha1.New, key)
	_ = binary.Write(mac, binary.BigEndian, step)
	sum := mac.Sum(nil)
	offset := sum[19] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:])&0x7fffffff)%1000000)
}

func currentStep() int64 { return time.Now().Unix() / 30 }

// wrongCode is a 6-digit code the app does not show around now.
func wrongCode(t *testing.T, secret string) string {
	t.Helper()
	now := currentStep()
	for n := 0; ; n++ {
		code := fmt.Sprintf("%06d", n)
		taken := false
		for step := now - 2; step <= now+2; step++ {
			taken = taken || totpAt(t, secret, step) == code
		}
		if !taken {
			return code
		}
	}
}

// turnOnTwoFactor enrolls an authenticator app for userID and confirms it, returning
// the secret and the recovery codes.
func turnOnTwoFactor(t *testing.T, k *authkit.AuthKit, userID string) (string, []string) {
	t.Helper()
	ctx := context.Background()
	enrollment, err := k.TwoFactorService().EnrollTOTP(ctx, userID)
	if err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	codes, err := k.TwoFactorService().ConfirmTOTP(ctx, userID, totpAt(t, enrollment.Secret, currentStep()))
	if err != nil {
		t.Fatalf("ConfirmTOTP: %v", err)
	}
	return enrollment.Secret, codes
}

// freshCode returns a code for the current step after clearing the record of the
// last step used, so a test can sign in again within the same 30 seconds.
func freshCode(t *testing.T, db *sql.DB, secret, userID string) string {
	t.Helper()
	if _, err := db.Exec("UPDATE authkit.totp_factors SET last_used_step = 0 WHERE user_id = $1", userID); err != nil {
		t.Fatal(err)
	}
	return totpAt(t, secret, currentStep())
}

// challengeFrom returns the challenge a login that needs a second factor returned.
func challengeFrom(t *testing.T, err error) string {
	t.Helper()
	var required *model.SecondFactorRequiredError
	if !errors.As(err, &required) || !errors.Is(err, authkit.ErrSecondFactorRequired) {
		t.Fatalf("login error = %v, want a SecondFactorRequiredError", err)
	}
	if required.Challenge == "" || time.Until(required.ExpiresAt) < 4*time.Minute {
		t.Fatalf("challenge %+v", required)
	}
	return required.Challenge
}

func complete(k *authkit.AuthKit, challenge, code string) (*model.InstallationLoginResponse, error) {
	return k.TwoFactorService().CompleteSecondFactor(context.Background(), model.CompleteSecondFactorRequest{Challenge: challenge, Code: code})
}

func userCounters(t *testing.T, db *sql.DB, userID string) (failed int, locked bool) {
	t.Helper()
	if err := db.QueryRow("SELECT failed_login_count, is_locked FROM authkit.users WHERE id = $1", userID).Scan(&failed, &locked); err != nil {
		t.Fatal(err)
	}
	return failed, locked
}

// Setting up an authenticator app, its recovery codes, and turning it off.
func TestTwoFactorEnrollment(t *testing.T) {
	db, k, _, userID := twoFactorFixture(t, authkit.SessionDisabled)
	ctx := context.Background()
	tf := k.TwoFactorService()
	email := "admin@" + historyTenant

	status, err := tf.Status(ctx, userID)
	if err != nil || status.Enabled || status.EnabledAt != nil || status.RecoveryCodesLeft != 0 {
		t.Fatalf("Status before: %+v, %v", status, err)
	}
	_, err = tf.ConfirmTOTP(ctx, userID, "123456")
	requireError(t, err, authkit.ErrNotFound)
	_, err = tf.EnrollTOTP(ctx, "00000000-0000-7000-8000-000000000000")
	requireError(t, err, authkit.ErrNotFound)

	first, err := tf.EnrollTOTP(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Secret) != 32 || !strings.HasPrefix(first.URI, "otpauth://totp/Acme%20Corp:"+email+"?") || !strings.Contains(first.URI, "secret="+first.Secret) {
		t.Fatalf("enrollment %+v", first)
	}
	// Until it is confirmed, it changes nothing.
	if _, err := historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant); err != nil {
		t.Fatalf("login with an unconfirmed app: %v", err)
	}
	// Enrolling again replaces the secret; the first one no longer confirms.
	second, err := tf.EnrollTOTP(ctx, userID)
	if err != nil || second.Secret == first.Secret {
		t.Fatalf("second enrollment %+v, %v", second, err)
	}
	_, err = tf.ConfirmTOTP(ctx, userID, totpAt(t, first.Secret, currentStep()))
	requireError(t, err, authkit.ErrInvalidSecondFactor)
	_, err = tf.ConfirmTOTP(ctx, userID, "not a code")
	requireError(t, err, authkit.ErrInvalidSecondFactor)

	// A code checked against a secret that a new enrollment has since replaced does
	// not confirm the new one.
	var oldCiphertext string
	if err := db.QueryRow("SELECT secret_ciphertext FROM authkit.totp_factors WHERE user_id=$1", userID).Scan(&oldCiphertext); err != nil {
		t.Fatal(err)
	}
	third, err := tf.EnrollTOTP(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	repo := repository.New(db, db)
	if err := repo.ConfirmTOTP(ctx, userID, oldCiphertext, currentStep(), nil); !errors.Is(err, authkit.ErrNotFound) {
		t.Fatalf("confirming a replaced secret: %v", err)
	}
	second = third

	codes, err := tf.ConfirmTOTP(ctx, userID, totpAt(t, second.Secret, currentStep()))
	if err != nil || len(codes) != 10 {
		t.Fatalf("ConfirmTOTP: %v, %v", codes, err)
	}
	status, err = tf.Status(ctx, userID)
	if err != nil || !status.Enabled || status.EnabledAt == nil || status.RecoveryCodesLeft != 10 {
		t.Fatalf("Status after: %+v, %v", status, err)
	}
	_, err = tf.ConfirmTOTP(ctx, userID, totpAt(t, second.Secret, currentStep()+1))
	requireError(t, err, authkit.ErrTwoFactorAlreadyEnabled)
	_, err = tf.EnrollTOTP(ctx, userID)
	requireError(t, err, authkit.ErrTwoFactorAlreadyEnabled)

	// Neither the secret nor the codes are stored as they are.
	var stored string
	if err := db.QueryRow("SELECT secret_ciphertext FROM authkit.totp_factors WHERE user_id=$1", userID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, "v1:") || strings.Contains(stored, second.Secret) {
		t.Fatalf("stored secret %q", stored)
	}
	for _, code := range codes {
		if n := countRows(t, db, "SELECT count(*) FROM authkit.recovery_codes WHERE code_hash IN ($1, $2)", code, strings.ReplaceAll(code, "-", "")); n != 0 {
			t.Fatal("a recovery code is stored as it is")
		}
	}

	// Verify spends a recovery code once, and counts a wrong code.
	if err := tf.Verify(ctx, userID, strings.ToUpper(codes[0])); err != nil {
		t.Fatalf("Verify recovery code: %v", err)
	}
	requireError(t, tf.Verify(ctx, userID, codes[0]), authkit.ErrInvalidSecondFactor)
	if failed, _ := userCounters(t, db, userID); failed != 1 {
		t.Fatalf("failed count %d after a wrong code, want 1", failed)
	}
	if err := tf.Verify(ctx, userID, freshCode(t, db, second.Secret, userID)); err != nil {
		t.Fatalf("Verify app code: %v", err)
	}

	// New recovery codes replace the old ones.
	fresh, err := tf.RegenerateRecoveryCodes(ctx, userID)
	if err != nil || len(fresh) != 10 {
		t.Fatalf("RegenerateRecoveryCodes: %v, %v", fresh, err)
	}
	requireError(t, tf.Verify(ctx, userID, codes[1]), authkit.ErrInvalidSecondFactor)
	if err := tf.Verify(ctx, userID, fresh[0]); err != nil {
		t.Fatalf("Verify new code: %v", err)
	}
	if status, _ := tf.Status(ctx, userID); status.RecoveryCodesLeft != 9 {
		t.Fatalf("%d codes left, want 9", status.RecoveryCodesLeft)
	}

	// Turning it off deletes everything and password logins stop asking.
	if err := tf.Disable(ctx, userID); err != nil {
		t.Fatal(err)
	}
	requireError(t, tf.Disable(ctx, userID), authkit.ErrNotFound)
	_, err = tf.RegenerateRecoveryCodes(ctx, userID)
	requireError(t, err, authkit.ErrNotFound)
	requireError(t, tf.Verify(ctx, userID, fresh[1]), authkit.ErrNotFound)
	if n := countRows(t, db, "SELECT count(*) FROM authkit.recovery_codes WHERE user_id=$1", userID); n != 0 {
		t.Fatalf("%d recovery codes left after Disable", n)
	}
	if status, _ := tf.Status(ctx, userID); status.Enabled || status.RecoveryCodesLeft != 0 {
		t.Fatalf("Status after Disable: %+v", status)
	}
	if _, err := historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant); err != nil {
		t.Fatalf("login after Disable: %v", err)
	}
}

// Every password login waits for the second factor, and finishes as it would have
// without it: same workspace, same installation, same history.
func TestTwoFactorPasswordLogins(t *testing.T) {
	for _, mode := range historyModes {
		t.Run(modeName(mode), func(t *testing.T) {
			db, k, m, userID := twoFactorFixture(t, mode)
			secret, codes := turnOnTwoFactor(t, k, userID)
			sessions := "SELECT count(*) FROM authkit.refresh_tokens"

			for _, tenantID := range []string{historyTenant, ""} {
				before := countRows(t, db, sessions)
				_, err := historyLogin(k, mode, "ValidPass1!", tenantID)
				challenge := challengeFrom(t, err)
				if countRows(t, db, sessions) != before {
					t.Fatal("the password alone opened a session")
				}

				_, err = complete(k, challenge, wrongCode(t, secret))
				requireError(t, err, authkit.ErrInvalidSecondFactor)
				code := freshCode(t, db, secret, userID)
				if tenantID == "" {
					code = codes[0]
				}
				resp, err := complete(k, challenge, code)
				if err != nil {
					t.Fatalf("CompleteSecondFactor: %v", err)
				}
				if resp.RefreshToken == "" || resp.AccessToken == "" || resp.TenantID != historyTenant || resp.User.ID != userID {
					t.Fatalf("response %+v", resp.LoginResponse)
				}
				if mode == authkit.SessionDisabled {
					if resp.Session != nil {
						t.Fatal("a session record without session support")
					}
					if _, err := k.AuthService().ValidateJWT(context.Background(), resp.AccessToken); err != nil {
						t.Fatalf("access token: %v", err)
					}
				} else {
					if resp.Session == nil || resp.Session.InstallationID != "laptop" || resp.Session.SignInMethod != "password" {
						t.Fatalf("session %+v", resp.Session)
					}
					if _, err := k.InstallationAuthService().ValidateInstallationJWT(context.Background(), resp.AccessToken); err != nil {
						t.Fatalf("access token: %v", err)
					}
				}
				_, err = complete(k, challenge, freshCode(t, db, secret, userID))
				requireError(t, err, authkit.ErrInvalidCredentials)
			}

			events := history(t, k, userID)
			if len(events) != 4 {
				t.Fatalf("%d events, want 4", len(events))
			}
			checkEvent(t, events[0], "password", "", historyTenant)
			checkEvent(t, events[1], "password", model.SignInFailureBadSecondFactor, "")
			checkEvent(t, events[2], "password", "", historyTenant)
			checkEvent(t, events[3], "password", model.SignInFailureBadSecondFactor, historyTenant)
			if events[2].IPAddress != "2001:db8::7" || events[2].DeviceName != "Work laptop" {
				t.Fatalf("the finished login lost where it came from: %+v", events[2])
			}
			if mode != authkit.SessionDisabled && (events[2].SessionID == "" || events[3].InstallationID != "laptop") {
				t.Fatalf("session and installation: %+v, %+v", events[2], events[3])
			}
			if n := m.get(metrics.CounterLoginFailure + "|reason=" + model.SignInFailureBadSecondFactor); n != 2 {
				t.Fatalf("%d bad-second-factor failures counted, want 2", n)
			}
			if n := m.get(metrics.CounterLoginSuccess); n != 2 {
				t.Fatalf("%d successes counted, want 2", n)
			}
		})
	}
}

// Wrong codes count toward the same lockout as wrong passwords, and the password
// alone does not reset the count.
func TestTwoFactorLockout(t *testing.T) {
	db, k, _, userID := twoFactorFixture(t, authkit.SessionDisabled)
	secret, _ := turnOnTwoFactor(t, k, userID)

	for range 2 {
		_, err := historyLogin(k, authkit.SessionDisabled, "WrongPass1!", historyTenant)
		requireError(t, err, authkit.ErrInvalidCredentials)
	}
	_, err := historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant)
	challenge := challengeFrom(t, err)
	if failed, _ := userCounters(t, db, userID); failed != 2 {
		t.Fatalf("failed count %d after the right password, want 2", failed)
	}
	_, err = complete(k, challenge, wrongCode(t, secret))
	requireError(t, err, authkit.ErrInvalidSecondFactor)
	if _, err := complete(k, challenge, freshCode(t, db, secret, userID)); err != nil {
		t.Fatal(err)
	}
	if failed, _ := userCounters(t, db, userID); failed != 0 {
		t.Fatalf("failed count %d after a whole sign-in, want 0", failed)
	}

	_, err = historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant)
	challenge = challengeFrom(t, err)
	for range 5 {
		_, err = complete(k, challenge, wrongCode(t, secret))
		requireError(t, err, authkit.ErrInvalidSecondFactor)
	}
	if failed, locked := userCounters(t, db, userID); failed != 5 || !locked {
		t.Fatalf("failed %d, locked %v after five wrong codes", failed, locked)
	}
	_, err = complete(k, challenge, freshCode(t, db, secret, userID))
	requireError(t, err, authkit.ErrAccountLocked)
	_, err = historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant)
	requireError(t, err, authkit.ErrInvalidCredentials)
}

// A code is accepted once, however many logins race for it, and a login finishes
// once, however many good codes race to finish it.
func TestTwoFactorReplay(t *testing.T) {
	db, k, _, userID := twoFactorFixture(t, authkit.SessionDisabled)
	secret, codes := turnOnTwoFactor(t, k, userID)

	code := freshCode(t, db, secret, userID)
	_, err := historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant)
	if _, err := complete(k, challengeFrom(t, err), code); err != nil {
		t.Fatal(err)
	}
	_, err = historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant)
	challenge := challengeFrom(t, err)
	_, err = complete(k, challenge, code)
	requireError(t, err, authkit.ErrInvalidSecondFactor)
	requireError(t, k.TwoFactorService().Verify(context.Background(), userID, code), authkit.ErrInvalidSecondFactor)
	// An older step's code is refused once a later one was used.
	_, err = complete(k, challenge, totpAt(t, secret, currentStep()-1))
	requireError(t, err, authkit.ErrInvalidSecondFactor)
	if _, err := complete(k, challenge, codes[0]); err != nil {
		t.Fatal(err)
	}
	_, err = historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant)
	_, err = complete(k, challengeFrom(t, err), codes[0])
	requireError(t, err, authkit.ErrInvalidSecondFactor)
	if _, err := db.Exec("UPDATE authkit.users SET failed_login_count = 0 WHERE id = $1", userID); err != nil {
		t.Fatal(err)
	}

	race := func(n int, finish func(i int) error) int {
		var wg sync.WaitGroup
		var mu sync.Mutex
		finished := 0
		for i := range n {
			wg.Go(func() {
				err := finish(i)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					finished++
				case !errors.Is(err, authkit.ErrInvalidSecondFactor) && !errors.Is(err, authkit.ErrInvalidCredentials):
					t.Errorf("finish %d: %v", i, err)
				}
			})
		}
		wg.Wait()
		return finished
	}
	// One app code, five logins.
	var challenges []string
	for range 5 {
		_, err := historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant)
		challenges = append(challenges, challengeFrom(t, err))
	}
	code = freshCode(t, db, secret, userID)
	if n := race(5, func(i int) error { _, err := complete(k, challenges[i], code); return err }); n != 1 {
		t.Fatalf("%d logins finished with one code, want 1", n)
	}
	// One login, five recovery codes.
	_, err = historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant)
	challenge = challengeFrom(t, err)
	if n := race(5, func(i int) error { _, err := complete(k, challenge, codes[1+i]); return err }); n != 1 {
		t.Fatalf("one login finished %d times, want 1", n)
	}
}

// A challenge is good for one login of one user, until it expires or two-factor is
// turned off, and only while the account stays usable.
func TestTwoFactorChallenge(t *testing.T) {
	db, k, _, userID := twoFactorFixture(t, authkit.SessionDisabled)
	ctx := context.Background()
	secret, codes := turnOnTwoFactor(t, k, userID)
	login := func() string {
		t.Helper()
		_, err := historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant)
		return challengeFrom(t, err)
	}

	for _, bad := range []string{"", "  ", "no-such-challenge"} {
		_, err := complete(k, bad, codes[0])
		requireError(t, err, authkit.ErrInvalidCredentials)
	}

	expire := func(challenge string) {
		t.Helper()
		sum := sha256.Sum256([]byte(challenge))
		if _, err := db.Exec("UPDATE authkit.second_factor_challenges SET expires_at = NOW() - interval '1 second' WHERE token_hash = $1", hex.EncodeToString(sum[:])); err != nil {
			t.Fatal(err)
		}
	}

	expired := login()
	expire(expired)
	_, err := complete(k, expired, codes[0])
	requireError(t, err, authkit.ErrInvalidCredentials)
	if n := countRows(t, db, "SELECT count(*) FROM authkit.second_factor_challenges"); n != 0 {
		t.Fatalf("%d challenges after the expired one was tried, want 0", n)
	}
	if status, _ := k.TwoFactorService().Status(ctx, userID); status.RecoveryCodesLeft != 10 {
		t.Fatal("an expired challenge spent a recovery code")
	}

	// CleanupExpired removes only expired ones. (A new login drops the user's
	// expired ones too, so this one comes last.)
	live := login()
	expire(login())
	n, err := k.TwoFactorService().CleanupExpired(ctx)
	if err != nil || n != 1 {
		t.Fatalf("CleanupExpired: %d, %v", n, err)
	}
	if left := countRows(t, db, "SELECT count(*) FROM authkit.second_factor_challenges"); left != 1 {
		t.Fatalf("%d challenges left, want 1", left)
	}

	// A disabled account cannot finish.
	if _, err := db.Exec("UPDATE authkit.users SET is_enabled = false WHERE id = $1", userID); err != nil {
		t.Fatal(err)
	}
	_, err = complete(k, live, freshCode(t, db, secret, userID))
	requireError(t, err, authkit.ErrAccountDisabled)
	if _, err := db.Exec("UPDATE authkit.users SET is_enabled = true WHERE id = $1", userID); err != nil {
		t.Fatal(err)
	}

	// A password change or a sign-out everywhere ends the logins waiting for a code.
	if _, err := db.Exec("DELETE FROM authkit.second_factor_challenges"); err != nil {
		t.Fatal(err)
	}
	live = login()
	if err := k.UserService().IncrementTokenVersion(ctx, userID); err != nil {
		t.Fatal(err)
	}
	_, err = complete(k, live, freshCode(t, db, secret, userID))
	requireError(t, err, authkit.ErrInvalidCredentials)
	if n := countRows(t, db, "SELECT count(*) FROM authkit.second_factor_challenges"); n != 0 {
		t.Fatalf("%d challenges left after the stale one was tried, want 0", n)
	}
	live = login()

	// Turning two-factor off drops the logins waiting for it.
	if err := k.TwoFactorService().Disable(ctx, userID); err != nil {
		t.Fatal(err)
	}
	_, err = complete(k, live, codes[0])
	requireError(t, err, authkit.ErrInvalidCredentials)
}

// Without TwoFactorConfig nothing asks for a second factor, OpenSession never does,
// and without the migration a configured kit's password logins fail cleanly.
func TestTwoFactorConfigAndMigration(t *testing.T) {
	db, k, _, userID := twoFactorFixture(t, authkit.SessionDisabled)
	ctx := context.Background()
	turnOnTwoFactor(t, k, userID)

	resp, err := k.VerifiedLoginService().OpenSession(ctx, model.OpenSessionRequest{UserID: userID, SignInMethod: "passkey", TenantID: historyTenant})
	if err != nil || resp.AccessToken == "" {
		t.Fatalf("OpenSession: %v", err)
	}

	off := twoFactorKit(t, db, authkit.SessionDisabled, false, nil)
	if _, err := historyLogin(off, authkit.SessionDisabled, "ValidPass1!", historyTenant); err != nil {
		t.Fatalf("login without TwoFactorConfig: %v", err)
	}
	_, err = off.TwoFactorService().Status(ctx, userID)
	requireError(t, err, authkit.ErrTwoFactorNotConfigured)
	_, err = complete(off, "challenge", "123456")
	requireError(t, err, authkit.ErrTwoFactorNotConfigured)

	applyMigration(t, db, "000009_two_factor.up.sql") // idempotent
	applyMigration(t, db, "000009_two_factor.down.sql")
	applyMigration(t, db, "000009_two_factor.down.sql")
	_, err = historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant)
	requireError(t, err, authkit.ErrInternal)
	if strings.Contains(err.Error(), "totp") {
		t.Fatalf("error leaks SQL: %v", err)
	}
	_, err = k.TwoFactorService().EnrollTOTP(ctx, userID)
	requireError(t, err, authkit.ErrInternal)

	applyMigration(t, db, "000009_two_factor.up.sql")
	if n := countRows(t, db, "SELECT count(*) FROM authkit.totp_factors"); n != 0 {
		t.Fatal("down migration kept factors")
	}
	if _, err := historyLogin(k, authkit.SessionDisabled, "ValidPass1!", historyTenant); err != nil {
		t.Fatalf("login after the migration is back: %v", err)
	}
}
