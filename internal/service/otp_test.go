// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/model"
)

const testTenantID = "acme.test"

// testOTPSecret keys the HMAC used to hash OTP codes at rest in these unit tests;
// otpHash reproduces the service's hashing so a fake can store the same value the
// service will compare against.
const testOTPSecret = "test-otp-hmac-secret-at-least-32-bytes-long" //nolint:gosec // G101: fixed test HMAC secret, not a real credential

func otpHash(code string) string {
	return (&OTPService{hmacSecret: testOTPSecret}).hashOTP(code)
}

type fakeOTPRepository struct {
	code       *repository.VerificationCode
	deleted    bool
	upserted   *repository.CreateVerificationCodeRequest
	cleanupErr error
}

func (f *fakeOTPRepository) matches(tenantID, email, purpose string) bool {
	return f.code != nil &&
		f.code.TenantID == tenantID &&
		f.code.Email == email &&
		f.code.Purpose == purpose
}

func (f *fakeOTPRepository) GetVerificationCode(ctx context.Context, tenantID, email, purpose string) (*repository.VerificationCode, error) {
	if !f.matches(tenantID, email, purpose) {
		// Mirror the real repository: not-found is reported as model.ErrNotFound
		// (the rate-limit check treats only ErrNotFound as "no active code" and
		// any other error as a hard failure).
		return nil, model.ErrNotFound
	}
	return f.code, nil
}

func (f *fakeOTPRepository) UpsertVerificationCode(ctx context.Context, req repository.CreateVerificationCodeRequest, rateLimit time.Duration) (bool, error) {
	f.upserted = &req
	f.code = &repository.VerificationCode{
		TenantID:  req.TenantID,
		Email:     req.Email,
		CodeHash:  req.CodeHash,
		Purpose:   req.Purpose,
		ExpiresAt: req.ExpiresAt,
	}
	return true, nil
}

func (f *fakeOTPRepository) ConsumeVerificationCode(ctx context.Context, tenantID, email, code, purpose string, maxAttempts int) (repository.OTPConsumeResult, error) {
	if !f.matches(tenantID, email, purpose) || time.Now().After(f.code.ExpiresAt) {
		return repository.OTPConsumeInvalid, nil
	}
	// Already locked out: the row is retained (its created_at keeps enforcing the
	// generation cooldown), so do NOT clear it — just report lockout.
	if maxAttempts > 0 && f.code.Attempts >= maxAttempts {
		return repository.OTPConsumeLockedOut, nil
	}
	if f.code.CodeHash == code {
		f.deleted = true
		f.code = nil
		return repository.OTPConsumeValid, nil
	}
	f.code.Attempts++
	// Lockout on the final wrong attempt also retains the row, mirroring the repo.
	if maxAttempts > 0 && f.code.Attempts >= maxAttempts {
		return repository.OTPConsumeLockedOut, nil
	}
	return repository.OTPConsumeInvalid, nil
}

func (f *fakeOTPRepository) DeleteVerificationCode(ctx context.Context, tenantID, email, purpose string) error {
	f.deleted = true
	f.code = nil
	return nil
}

func (f *fakeOTPRepository) DeleteExpiredVerificationCodes(ctx context.Context) (int64, error) {
	if f.cleanupErr != nil {
		return 0, f.cleanupErr
	}
	return 3, nil
}

func TestOTPValidateRejectsPurposeMismatch(t *testing.T) {
	repo := &fakeOTPRepository{
		code: &repository.VerificationCode{
			TenantID:  testTenantID,
			Email:     "user@example.com",
			CodeHash:  otpHash("123456"),
			Purpose:   "signup",
			ExpiresAt: time.Now().Add(time.Minute),
			CreatedAt: time.Now().Add(-time.Minute),
		},
	}
	service := &OTPService{repo: repo, rateLimitDuration: time.Minute, hmacSecret: testOTPSecret, logger: ensureLogger(nil)}

	err := service.Validate(context.Background(), model.OTPValidateRequest{TenantID: testTenantID, Email: "user@example.com", Code: "123456", Purpose: "reset-password"})
	if err == nil {
		t.Fatal("expected purpose mismatch to fail")
	}
	if repo.deleted {
		t.Fatal("purpose mismatch should not delete the stored OTP")
	}
}

func TestOTPValidateRejectsTenantMismatch(t *testing.T) {
	repo := &fakeOTPRepository{
		code: &repository.VerificationCode{
			TenantID:  testTenantID,
			Email:     "user@example.com",
			CodeHash:  otpHash("123456"),
			Purpose:   "signup",
			ExpiresAt: time.Now().Add(time.Minute),
			CreatedAt: time.Now().Add(-time.Minute),
		},
	}
	service := &OTPService{repo: repo, rateLimitDuration: time.Minute, hmacSecret: testOTPSecret, logger: ensureLogger(nil)}

	if err := service.Validate(context.Background(), model.OTPValidateRequest{TenantID: "other.test", Email: "user@example.com", Code: "123456", Purpose: "signup"}); err == nil {
		t.Fatal("expected OTP from another tenant to be rejected")
	}
	if repo.deleted {
		t.Fatal("cross-tenant validation should not delete the stored OTP")
	}
}

func TestOTPValidateDeletesMatchingCodeWithNilLogger(t *testing.T) {
	repo := &fakeOTPRepository{
		code: &repository.VerificationCode{
			TenantID:  testTenantID,
			Email:     "user@example.com",
			CodeHash:  otpHash("123456"),
			Purpose:   "signup",
			ExpiresAt: time.Now().Add(time.Minute),
			CreatedAt: time.Now().Add(-time.Minute),
		},
	}
	service := &OTPService{repo: repo, rateLimitDuration: time.Minute, hmacSecret: testOTPSecret, logger: ensureLogger(nil)}

	if err := service.Validate(context.Background(), model.OTPValidateRequest{TenantID: testTenantID, Email: "user@example.com", Code: "123456", Purpose: "signup"}); err != nil {
		t.Fatalf("expected validation to succeed: %v", err)
	}
	if !repo.deleted {
		t.Fatal("valid OTP should be deleted after validation")
	}
}

func TestOTPValidateLocksOutAfterMaxAttempts(t *testing.T) {
	repo := &fakeOTPRepository{
		code: &repository.VerificationCode{
			TenantID:  testTenantID,
			Email:     "user@example.com",
			CodeHash:  otpHash("123456"),
			Purpose:   "signup",
			ExpiresAt: time.Now().Add(time.Minute),
			CreatedAt: time.Now().Add(-time.Minute),
		},
	}
	service := &OTPService{repo: repo, rateLimitDuration: time.Minute, hmacSecret: testOTPSecret, logger: ensureLogger(nil)}

	// MaxOTPValidationAttempts-1 wrong guesses keep returning the generic error.
	for i := 0; i < MaxOTPValidationAttempts-1; i++ {
		err := service.Validate(context.Background(), model.OTPValidateRequest{TenantID: testTenantID, Email: "user@example.com", Code: "000000", Purpose: "signup"})
		if err == nil || !strings.Contains(err.Error(), "invalid or expired OTP") {
			t.Fatalf("attempt %d: expected invalid OTP error, got %v", i+1, err)
		}
		if repo.deleted {
			t.Fatalf("attempt %d: code should not be deleted before lockout", i+1)
		}
	}

	// The final wrong guess trips the lockout.
	err := service.Validate(context.Background(), model.OTPValidateRequest{TenantID: testTenantID, Email: "user@example.com", Code: "000000", Purpose: "signup"})
	if err == nil || !strings.Contains(err.Error(), "too many invalid attempts") {
		t.Fatalf("expected lockout error, got %v", err)
	}

	// The locked-out code is retained (not deleted): its row keeps enforcing the
	// generation cooldown so a burst of wrong guesses can't reset the rate limit.
	if repo.deleted {
		t.Fatal("locked-out code should be retained as a rate-limit tombstone, not deleted")
	}
	if repo.code == nil {
		t.Fatal("locked-out code row should still exist")
	}

	// Even the correct code no longer works once locked out — it keeps rejecting.
	if err := service.Validate(context.Background(), model.OTPValidateRequest{TenantID: testTenantID, Email: "user@example.com", Code: "123456", Purpose: "signup"}); err == nil || !strings.Contains(err.Error(), "too many invalid attempts") {
		t.Fatalf("expected locked-out code to keep rejecting, got %v", err)
	}
}

func TestOTPGenerateRateLimitWithNilLogger(t *testing.T) {
	repo := &fakeOTPRepository{
		code: &repository.VerificationCode{
			TenantID:  testTenantID,
			Email:     "user@example.com",
			CodeHash:  otpHash("123456"),
			Purpose:   "signup",
			ExpiresAt: time.Now().Add(time.Minute),
			CreatedAt: time.Now().Add(-10 * time.Second),
		},
	}
	service := &OTPService{repo: repo, rateLimitDuration: time.Minute, hmacSecret: testOTPSecret, logger: ensureLogger(nil)}

	_, err := service.Generate(context.Background(), model.OTPGenerateRequest{TenantID: testTenantID, Email: "user@example.com", Purpose: "signup", ExpirationDuration: time.Minute})
	if err == nil {
		t.Fatal("expected rate limit error")
	}
	if !errors.Is(err, model.ErrOTPRateLimited) {
		t.Fatalf("expected ErrOTPRateLimited, got %v", err)
	}
}

func TestOTPGenerateRateLimitedAfterLockout(t *testing.T) {
	// A code that has been locked out (max wrong attempts) but is still within the
	// generation cooldown must NOT let a fresh code be issued. The lockout row is
	// retained precisely so its created_at keeps enforcing the cooldown — otherwise
	// failing a code 5 times would wipe the rate limit and allow OTP-email spam.
	repo := &fakeOTPRepository{
		code: &repository.VerificationCode{
			TenantID:  testTenantID,
			Email:     "user@example.com",
			CodeHash:  otpHash("123456"),
			Purpose:   "signup",
			Attempts:  MaxOTPValidationAttempts, // already locked out
			ExpiresAt: time.Now().Add(time.Minute),
			CreatedAt: time.Now().Add(-10 * time.Second), // within the 1-minute cooldown
		},
	}
	service := &OTPService{repo: repo, rateLimitDuration: time.Minute, hmacSecret: testOTPSecret, logger: ensureLogger(nil)}

	_, err := service.Generate(context.Background(), model.OTPGenerateRequest{
		TenantID: testTenantID, Email: "user@example.com", Purpose: "signup", ExpirationDuration: time.Minute,
	})
	if !errors.Is(err, model.ErrOTPRateLimited) {
		t.Fatalf("expected ErrOTPRateLimited after lockout within cooldown, got %v", err)
	}
	if repo.upserted != nil {
		t.Fatal("rate-limited generation must not upsert a new code")
	}
}

func TestOTPGenerateAndCleanup(t *testing.T) {
	repo := &fakeOTPRepository{}
	service := &OTPService{repo: repo, rateLimitDuration: time.Minute, hmacSecret: testOTPSecret, logger: ensureLogger(nil)}

	response, err := service.Generate(context.Background(), model.OTPGenerateRequest{TenantID: testTenantID, Email: "user@example.com", Purpose: "signup", ExpirationDuration: time.Minute})
	if err != nil {
		t.Fatalf("generate OTP: %v", err)
	}
	if len(response.Code) != 6 {
		t.Fatalf("code length = %d, want 6", len(response.Code))
	}
	for _, ch := range response.Code {
		if ch < '0' || ch > '9' {
			t.Fatalf("code contains non-digit %q", ch)
		}
	}
	if repo.upserted == nil {
		t.Fatal("expected code to be upserted")
	}
	// Only the keyed HMAC of the code is persisted, never the plaintext.
	if repo.upserted.CodeHash != otpHash(response.Code) || repo.upserted.Purpose != "signup" || repo.upserted.TenantID != testTenantID {
		t.Fatalf("unexpected upsert request: %+v", repo.upserted)
	}
	if repo.upserted.CodeHash == response.Code {
		t.Fatal("stored value must be the HMAC, not the plaintext OTP")
	}

	deleted, err := service.CleanupExpired(context.Background())
	if err != nil {
		t.Fatalf("cleanup expired: %v", err)
	}
	if deleted != 3 {
		t.Fatalf("deleted = %d, want 3", deleted)
	}
}

func TestOTPGenerateRejectsNonPositiveExpiration(t *testing.T) {
	repo := &fakeOTPRepository{}
	service := &OTPService{repo: repo, rateLimitDuration: time.Minute, hmacSecret: testOTPSecret, logger: ensureLogger(nil)}

	// Zero (the zero value of a forgotten field) and negative durations must be
	// rejected before any work — otherwise the code would be born already expired.
	for _, d := range []time.Duration{0, -time.Minute} {
		_, err := service.Generate(context.Background(), model.OTPGenerateRequest{
			TenantID: testTenantID, Email: "user@example.com", Purpose: "signup", ExpirationDuration: d,
		})
		if err == nil {
			t.Fatalf("ExpirationDuration=%s: expected an error, got nil", d)
		}
		if repo.upserted != nil {
			t.Fatalf("ExpirationDuration=%s: must be rejected before any upsert", d)
		}
	}
}

func TestOTPRequiresHMACSecret(t *testing.T) {
	// With no HMAC secret configured, both Generate and Validate must fail with the
	// matchable sentinel rather than silently hashing with an empty key.
	svc := &OTPService{repo: &fakeOTPRepository{}, rateLimitDuration: time.Minute, logger: ensureLogger(nil)}

	if _, err := svc.Generate(context.Background(), model.OTPGenerateRequest{
		TenantID: testTenantID, Email: "u@" + testTenantID, Purpose: "signup", ExpirationDuration: time.Minute,
	}); !errors.Is(err, model.ErrOTPSecretMissing) {
		t.Fatalf("Generate without secret: expected ErrOTPSecretMissing, got %v", err)
	}

	if err := svc.Validate(context.Background(), model.OTPValidateRequest{
		TenantID: testTenantID, Email: "u@" + testTenantID, Code: "123456", Purpose: "signup",
	}); !errors.Is(err, model.ErrOTPSecretMissing) {
		t.Fatalf("Validate without secret: expected ErrOTPSecretMissing, got %v", err)
	}
}

func TestGenerateSecureOTPRejectsInvalidLength(t *testing.T) {
	if _, err := generateSecureOTP(0); err == nil {
		t.Fatal("expected invalid OTP length to fail")
	}
}

func TestOTPValidateRejectsExpiredCode(t *testing.T) {
	repo := &fakeOTPRepository{
		code: &repository.VerificationCode{
			TenantID:  testTenantID,
			Email:     "user@example.com",
			CodeHash:  otpHash("123456"),
			Purpose:   "signup",
			ExpiresAt: time.Now().Add(-time.Minute),
			CreatedAt: time.Now().Add(-2 * time.Minute),
		},
	}
	service := &OTPService{repo: repo, rateLimitDuration: time.Minute, hmacSecret: testOTPSecret, logger: ensureLogger(nil)}

	// Even with the correct code, an expired OTP surfaces ErrInvalidOTP.
	err := service.Validate(context.Background(), model.OTPValidateRequest{TenantID: testTenantID, Email: "user@example.com", Code: "123456", Purpose: "signup"})
	if !errors.Is(err, model.ErrInvalidOTP) {
		t.Fatalf("expected ErrInvalidOTP for expired code, got %v", err)
	}
}
