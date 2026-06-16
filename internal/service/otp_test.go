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
		Code:      req.Code,
		Purpose:   req.Purpose,
		ExpiresAt: req.ExpiresAt,
	}
	return true, nil
}

func (f *fakeOTPRepository) ConsumeVerificationCode(ctx context.Context, tenantID, email, code, purpose string, maxAttempts int) (repository.OTPConsumeResult, error) {
	if !f.matches(tenantID, email, purpose) || time.Now().After(f.code.ExpiresAt) {
		return repository.OTPConsumeInvalid, nil
	}
	if maxAttempts > 0 && f.code.Attempts >= maxAttempts {
		f.deleted = true
		f.code = nil
		return repository.OTPConsumeLockedOut, nil
	}
	if f.code.Code == code {
		f.deleted = true
		f.code = nil
		return repository.OTPConsumeValid, nil
	}
	f.code.Attempts++
	if maxAttempts > 0 && f.code.Attempts >= maxAttempts {
		f.deleted = true
		f.code = nil
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
			Code:      "123456",
			Purpose:   "signup",
			ExpiresAt: time.Now().Add(time.Minute),
			CreatedAt: time.Now().Add(-time.Minute),
		},
	}
	service := &OTPService{repo: repo, rateLimitDuration: time.Minute}

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
			Code:      "123456",
			Purpose:   "signup",
			ExpiresAt: time.Now().Add(time.Minute),
			CreatedAt: time.Now().Add(-time.Minute),
		},
	}
	service := &OTPService{repo: repo, rateLimitDuration: time.Minute}

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
			Code:      "123456",
			Purpose:   "signup",
			ExpiresAt: time.Now().Add(time.Minute),
			CreatedAt: time.Now().Add(-time.Minute),
		},
	}
	service := &OTPService{repo: repo, rateLimitDuration: time.Minute}

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
			Code:      "123456",
			Purpose:   "signup",
			ExpiresAt: time.Now().Add(time.Minute),
			CreatedAt: time.Now().Add(-time.Minute),
		},
	}
	service := &OTPService{repo: repo, rateLimitDuration: time.Minute}

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

	// The final wrong guess trips the lockout and invalidates the code.
	err := service.Validate(context.Background(), model.OTPValidateRequest{TenantID: testTenantID, Email: "user@example.com", Code: "000000", Purpose: "signup"})
	if err == nil || !strings.Contains(err.Error(), "too many invalid attempts") {
		t.Fatalf("expected lockout error, got %v", err)
	}
	if !repo.deleted {
		t.Fatal("code should be invalidated after lockout")
	}

	// Even the correct code no longer works once locked out / removed.
	if err := service.Validate(context.Background(), model.OTPValidateRequest{TenantID: testTenantID, Email: "user@example.com", Code: "123456", Purpose: "signup"}); err == nil {
		t.Fatal("expected validation to fail after lockout removed the code")
	}
}

func TestOTPGenerateRateLimitWithNilLogger(t *testing.T) {
	repo := &fakeOTPRepository{
		code: &repository.VerificationCode{
			TenantID:  testTenantID,
			Email:     "user@example.com",
			Code:      "123456",
			Purpose:   "signup",
			ExpiresAt: time.Now().Add(time.Minute),
			CreatedAt: time.Now().Add(-10 * time.Second),
		},
	}
	service := &OTPService{repo: repo, rateLimitDuration: time.Minute}

	_, err := service.Generate(context.Background(), model.OTPGenerateRequest{TenantID: testTenantID, Email: "user@example.com", Purpose: "signup", ExpirationDuration: time.Minute})
	if err == nil {
		t.Fatal("expected rate limit error")
	}
	if !errors.Is(err, model.ErrOTPRateLimited) {
		t.Fatalf("expected ErrOTPRateLimited, got %v", err)
	}
}

func TestOTPGenerateAndCleanup(t *testing.T) {
	repo := &fakeOTPRepository{}
	service := &OTPService{repo: repo, rateLimitDuration: time.Minute}

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
	if repo.upserted.Code != response.Code || repo.upserted.Purpose != "signup" || repo.upserted.TenantID != testTenantID {
		t.Fatalf("unexpected upsert request: %+v", repo.upserted)
	}

	deleted, err := service.CleanupExpired(context.Background())
	if err != nil {
		t.Fatalf("cleanup expired: %v", err)
	}
	if deleted != 3 {
		t.Fatalf("deleted = %d, want 3", deleted)
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
			Code:      "123456",
			Purpose:   "signup",
			ExpiresAt: time.Now().Add(-time.Minute),
			CreatedAt: time.Now().Add(-2 * time.Minute),
		},
	}
	service := &OTPService{repo: repo, rateLimitDuration: time.Minute}

	// Even with the correct code, an expired OTP surfaces ErrInvalidOTP.
	err := service.Validate(context.Background(), model.OTPValidateRequest{TenantID: testTenantID, Email: "user@example.com", Code: "123456", Purpose: "signup"})
	if !errors.Is(err, model.ErrInvalidOTP) {
		t.Fatalf("expected ErrInvalidOTP for expired code, got %v", err)
	}
}
