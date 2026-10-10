// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/model"
)

// The SHA-1 test vectors of RFC 6238 Appendix B, cut to 6 digits.
func TestTOTPCodeMatchesRFC6238(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{
		59:          "287082",
		1111111109:  "081804",
		1111111111:  "050471",
		1234567890:  "005924",
		2000000000:  "279037",
		20000000000: "353130",
	} {
		if got := totpCode(secret, totpStep(time.Unix(unix, 0))); got != want {
			t.Errorf("code at %d = %s, want %s", unix, got, want)
		}
	}
}

func TestMatchTOTPAcceptsOneStepEitherSide(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1234567890, 0)
	current := totpStep(now)
	for _, step := range []int64{current - 1, current, current + 1} {
		got, ok := matchTOTP(secret, totpCode(secret, step), now)
		if !ok || got != step {
			t.Errorf("code for step %+d: got step %d, %v", step-current, got, ok)
		}
	}
	for _, step := range []int64{current - 2, current + 2} {
		if _, ok := matchTOTP(secret, totpCode(secret, step), now); ok {
			t.Errorf("code for step %+d accepted", step-current)
		}
	}
	if _, ok := matchTOTP(secret, totpCode([]byte("another secret, 20 b"), current), now); ok {
		t.Error("another secret's code accepted")
	}
}

func TestIsTOTPCode(t *testing.T) {
	for code, want := range map[string]bool{
		"123456": true, "000000": true, "12345": false, "1234567": false, "12345a": false, "": false, "١٢٣٤٥٦": false,
	} {
		if got := isTOTPCode(code); got != want {
			t.Errorf("isTOTPCode(%q) = %v", code, got)
		}
	}
}

func testTwoFactorKeys(t *testing.T, seed byte) *TwoFactorKeys {
	t.Helper()
	keys, err := NewTwoFactorKeys(bytes.Repeat([]byte{seed}, 32), "Acme")
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestNewTwoFactorKeysNeeds32Bytes(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := NewTwoFactorKeys(make([]byte, n), "Acme"); err == nil {
			t.Errorf("%d-byte key accepted", n)
		}
	}
}

func TestRecoveryCodes(t *testing.T) {
	keys := testTwoFactorKeys(t, 1)
	codes, hashes, err := keys.newRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != recoveryCodeCount || len(hashes) != recoveryCodeCount {
		t.Fatalf("got %d codes and %d hashes", len(codes), len(hashes))
	}
	seen := map[string]bool{}
	for i, code := range codes {
		if len(code) != 19 || strings.Count(code, "-") != 3 || code != strings.ToLower(code) {
			t.Errorf("code %q is not xxxx-xxxx-xxxx-xxxx", code)
		}
		if seen[code] {
			t.Errorf("code %q repeated", code)
		}
		seen[code] = true
		// People type them in any case, with or without the dashes.
		for _, typed := range []string{code, strings.ToUpper(code), strings.ReplaceAll(code, "-", ""), strings.ReplaceAll(code, "-", " ")} {
			normalized, ok := normalizeRecoveryCode(typed)
			if !ok || keys.recoveryHash(normalized) != hashes[i] {
				t.Errorf("typed %q does not match its hash", typed)
			}
		}
	}
	normalized, _ := normalizeRecoveryCode(codes[0])
	if testTwoFactorKeys(t, 2).recoveryHash(normalized) == hashes[0] {
		t.Error("another key gives the same hash")
	}
	for _, typed := range []string{"", "abcd-efgh-ijkl-mno", "abcd-efgh-ijkl-mnopq", "abcd-efgh-ijkl-mn01", "abcd-efgh-ijkl-mn8!"} {
		if _, ok := normalizeRecoveryCode(typed); ok {
			t.Errorf("normalizeRecoveryCode(%q) accepted", typed)
		}
	}
}

// A sealed secret opens only for its own user and key.
func TestTOTPSecretIsBoundToUserAndKey(t *testing.T) {
	keys := testTwoFactorKeys(t, 1)
	secret := []byte("12345678901234567890")
	sealed, err := keys.seal("user-1", secret)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, totpCipherV1Prefix) || strings.Contains(sealed, string(secret)) {
		t.Fatalf("sealed = %q", sealed)
	}
	if got, err := keys.open("user-1", sealed); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("open = %q, %v", got, err)
	}
	again, _ := keys.seal("user-1", secret)
	if again == sealed {
		t.Error("sealing twice gave the same ciphertext")
	}
	if _, err := keys.open("user-2", sealed); err == nil {
		t.Error("opened for another user")
	}
	if _, err := testTwoFactorKeys(t, 2).open("user-1", sealed); err == nil {
		t.Error("opened with another key")
	}
	tampered := []byte(sealed)
	tampered[len(tampered)-2] ^= 1
	for _, bad := range []string{string(tampered), strings.TrimPrefix(sealed, totpCipherV1Prefix), "v1:", "v1:%%%"} {
		if _, err := keys.open("user-1", bad); err == nil {
			t.Errorf("opened %q", bad)
		}
	}
}

func TestTOTPURI(t *testing.T) {
	secret := []byte("12345678901234567890")
	u, err := url.Parse(totpURI("Acme Corp", "alice@example.com", secret))
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Path != "/Acme Corp:alice@example.com" {
		t.Errorf("uri = %s", u)
	}
	if strings.Contains(u.RawQuery, "+") {
		t.Errorf("query %q encodes a space as +, which some apps show", u.RawQuery)
	}
	q := u.Query()
	want := map[string]string{ //nolint:gosec // G101 false positive: the RFC 6238 test secret
		"secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "issuer": "Acme Corp",
		"algorithm": "SHA1", "digits": "6", "period": "30",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
}

// fakeTwoFactorStore serves the password step's two calls; the rest of the
// interface is left nil and panics if reached.
type fakeTwoFactorStore struct {
	twoFactorStore
	enabled    bool
	enabledErr error
	challenges map[string]repository.SecondFactorChallenge
}

func (f *fakeTwoFactorStore) TwoFactorEnabled(ctx context.Context, userID string) (bool, error) {
	return f.enabled, f.enabledErr
}

func (f *fakeTwoFactorStore) InsertSecondFactorChallenge(ctx context.Context, tokenHash, userID string, login []byte, expiresAt time.Time) error {
	if f.challenges == nil {
		f.challenges = map[string]repository.SecondFactorChallenge{}
	}
	f.challenges[tokenHash] = repository.SecondFactorChallenge{UserID: userID, Login: login, ExpiresAt: expiresAt}
	return nil
}

// A right password for a user with two-factor on opens nothing and leaves the
// failed-login count alone: only the whole sign-in resets it.
func TestPasswordLoginWaitsForSecondFactor(t *testing.T) {
	user := makeUser(t, "correct-horse")
	user.FailedLoginCount = 3
	repo := &fakeAuthRepository{user: user, membership: makeMembership(user.ID)}
	store := &fakeTwoFactorStore{enabled: true}
	svc := newTestAuthService(repo)
	svc.twoFactorStore, svc.twoFactorKeys = store, testTwoFactorKeys(t, 1)

	info := &model.SessionInfo{IPAddress: "203.0.113.7"}
	_, err := svc.Login(context.Background(), model.LoginRequest{Email: user.Email, Password: "correct-horse", TenantID: testTenantID, SessionInfo: info})
	var required *model.SecondFactorRequiredError
	if !errors.As(err, &required) || !errors.Is(err, model.ErrSecondFactorRequired) {
		t.Fatalf("Login error = %v, want a SecondFactorRequiredError", err)
	}
	if len(required.Challenge) != 43 || time.Until(required.ExpiresAt) <= 4*time.Minute {
		t.Errorf("challenge %q expires %v", required.Challenge, required.ExpiresAt)
	}
	pending, ok := store.challenges[challengeHash(required.Challenge)]
	if !ok || len(store.challenges) != 1 || pending.UserID != user.ID {
		t.Fatalf("stored challenges = %v", store.challenges)
	}
	var login pendingLogin
	if err := json.Unmarshal(pending.Login, &login); err != nil {
		t.Fatal(err)
	}
	if login.Kind != pendingLoginTenant || login.TenantID != testTenantID || login.Installation || login.SessionInfo == nil || login.SessionInfo.IPAddress != "203.0.113.7" {
		t.Errorf("pending login = %+v", login)
	}
	if repo.unlockCalled || repo.updateLastLogin != 0 || repo.getMembershipCalled {
		t.Errorf("password step went on: unlock %v, last login %d, membership %v", repo.unlockCalled, repo.updateLastLogin, repo.getMembershipCalled)
	}
	if user.FailedLoginCount != 3 {
		t.Errorf("failed count = %d, want 3", user.FailedLoginCount)
	}
}

// A wrong password is refused as before, without a challenge, whether or not the
// user has two-factor on.
func TestWrongPasswordGetsNoChallenge(t *testing.T) {
	user := makeUser(t, "correct-horse")
	repo := &fakeAuthRepository{user: user, membership: makeMembership(user.ID)}
	store := &fakeTwoFactorStore{enabled: true}
	svc := newTestAuthService(repo)
	svc.twoFactorStore, svc.twoFactorKeys = store, testTwoFactorKeys(t, 1)
	_, err := svc.LoginByEmail(context.Background(), model.LoginByEmailRequest{Email: user.Email, Password: "wrong"})
	if !errors.Is(err, model.ErrInvalidCredentials) || len(store.challenges) != 0 {
		t.Fatalf("err = %v, challenges = %d", err, len(store.challenges))
	}
}

func TestPasswordLoginWithoutTwoFactorGoesOn(t *testing.T) {
	user := makeUser(t, "correct-horse")
	user.FailedLoginCount = 2
	repo := &fakeAuthRepository{user: user} // no membership: the login stops at the workspace gate
	svc := newTestAuthService(repo)
	svc.twoFactorStore, svc.twoFactorKeys = &fakeTwoFactorStore{}, testTwoFactorKeys(t, 1)
	_, err := svc.Login(context.Background(), model.LoginRequest{Email: user.Email, Password: "correct-horse", TenantID: testTenantID})
	if !errors.Is(err, model.ErrNoActiveMembership) {
		t.Fatalf("err = %v, want ErrNoActiveMembership", err)
	}
	if !repo.unlockCalled || repo.updateLastLogin != 1 {
		t.Errorf("unlock %v, last login %d", repo.unlockCalled, repo.updateLastLogin)
	}
}

// A failure to read the two-factor state stops the login: it never skips the
// second factor.
func TestTwoFactorReadFailureStopsLogin(t *testing.T) {
	user := makeUser(t, "correct-horse")
	repo := &fakeAuthRepository{user: user, membership: makeMembership(user.ID)}
	svc := newTestAuthService(repo)
	svc.twoFactorStore = &fakeTwoFactorStore{enabledErr: errors.New("relation \"totp_factors\" does not exist")}
	svc.twoFactorKeys = testTwoFactorKeys(t, 1)
	_, err := svc.Login(context.Background(), model.LoginRequest{Email: user.Email, Password: "correct-horse", TenantID: testTenantID})
	if !errors.Is(err, model.ErrInternal) || strings.Contains(err.Error(), "totp_factors") {
		t.Fatalf("err = %v, want a sanitized ErrInternal", err)
	}
	if repo.updateLastLogin != 0 || repo.getMembershipCalled {
		t.Error("login went on")
	}
}

func TestTwoFactorServiceNotConfigured(t *testing.T) {
	svc := NewTwoFactorService(nil, nil, nil, nil, nil)
	ctx := context.Background()
	_, enrollErr := svc.EnrollTOTP(ctx, "u")
	_, confirmErr := svc.ConfirmTOTP(ctx, "u", "123456")
	_, codesErr := svc.RegenerateRecoveryCodes(ctx, "u")
	_, statusErr := svc.Status(ctx, "u")
	_, completeErr := svc.CompleteSecondFactor(ctx, model.CompleteSecondFactorRequest{Challenge: "c", Code: "123456"})
	_, cleanupErr := svc.CleanupExpired(ctx)
	for name, err := range map[string]error{
		"EnrollTOTP": enrollErr, "ConfirmTOTP": confirmErr, "Verify": svc.Verify(ctx, "u", "123456"), "Disable": svc.Disable(ctx, "u"),
		"RegenerateRecoveryCodes": codesErr, "Status": statusErr, "CompleteSecondFactor": completeErr, "CleanupExpired": cleanupErr,
	} {
		if !errors.Is(err, model.ErrTwoFactorNotConfigured) {
			t.Errorf("%s: %v, want ErrTwoFactorNotConfigured", name, err)
		}
	}
}

func TestTwoFactorServiceNeedsUserID(t *testing.T) {
	svc := NewTwoFactorService(nil, nil, testTwoFactorKeys(t, 1), nil, nil)
	if _, err := svc.EnrollTOTP(context.Background(), ""); !errors.Is(err, model.ErrInvalidInput) {
		t.Errorf("EnrollTOTP: %v", err)
	}
	if err := svc.Disable(context.Background(), ""); !errors.Is(err, model.ErrInvalidInput) {
		t.Errorf("Disable: %v", err)
	}
}
