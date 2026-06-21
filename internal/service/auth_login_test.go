// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/model"
)

// fakeAuthRepository is an in-memory authRepository for unit-testing the
// security-critical AuthService logic (lockout, enumeration, revocation checks)
// without a database.
type fakeAuthRepository struct {
	user *model.User

	getByEmailErr error
	getByIDErr    error

	lastGetByEmail              string
	lockCalled                  bool
	unlockCalled                bool
	incFailedCalled             int
	updateLastLogin             int
	lockedUntilPassed           *time.Time
	getByIDFromPrimaryCalled    bool
	getByEmailFromPrimaryCalled bool
}

func (f *fakeAuthRepository) GetByEmail(ctx context.Context, email, tenantID string) (*model.User, error) {
	f.lastGetByEmail = email
	if f.getByEmailErr != nil {
		return nil, f.getByEmailErr
	}
	return f.user, nil
}

// GetByEmailFromPrimary mirrors GetByEmail for the fake; the primary/replica split
// is a repository concern, so the in-memory fake serves both from the same record.
func (f *fakeAuthRepository) GetByEmailFromPrimary(ctx context.Context, email, tenantID string) (*model.User, error) {
	f.getByEmailFromPrimaryCalled = true
	return f.GetByEmail(ctx, email, tenantID)
}

func (f *fakeAuthRepository) GetByID(ctx context.Context, userID uuid.UUID, tenantID string) (*model.User, error) {
	if f.getByIDErr != nil {
		return nil, f.getByIDErr
	}
	return f.user, nil
}

// GetByIDFromPrimary mirrors GetByID for the fake: the primary/replica split is a
// repository concern, so the in-memory fake returns the same user from both. It
// records that it was called so a test can assert the security gate uses it.
func (f *fakeAuthRepository) GetByIDFromPrimary(ctx context.Context, userID uuid.UUID, tenantID string) (*model.User, error) {
	f.getByIDFromPrimaryCalled = true
	return f.GetByID(ctx, userID, tenantID)
}

func (f *fakeAuthRepository) Lock(ctx context.Context, userID uuid.UUID, lockedUntil *time.Time) error {
	f.lockCalled = true
	f.lockedUntilPassed = lockedUntil
	return nil
}

func (f *fakeAuthRepository) UnlockByTenant(ctx context.Context, userID uuid.UUID, tenantID string) error {
	f.unlockCalled = true
	if f.user != nil {
		f.user.IsLocked = false
		f.user.FailedLoginCount = 0
	}
	return nil
}

func (f *fakeAuthRepository) RegisterFailedLogin(ctx context.Context, userID uuid.UUID, maxAttempts int, lockDuration time.Duration) (int, bool, error) {
	count := 0
	if f.user != nil {
		f.user.FailedLoginCount++
		count = f.user.FailedLoginCount
	}
	locked := maxAttempts > 0 && count >= maxAttempts
	if locked {
		f.lockCalled = true
		until := time.Now().Add(lockDuration)
		f.lockedUntilPassed = &until
		if f.user != nil {
			f.user.IsLocked = true
		}
	} else {
		f.incFailedCalled++
	}
	return count, locked, nil
}

func (f *fakeAuthRepository) UpdateLastLoginByTenant(ctx context.Context, userID uuid.UUID, tenantID string) error {
	f.updateLastLogin++
	return nil
}

func (f *fakeAuthRepository) VerifyPasswordByTenant(ctx context.Context, userID uuid.UUID, tenantID string) (string, error) {
	if f.user == nil {
		return "", model.ErrNotFound
	}
	return f.user.PasswordHash, nil
}

func (f *fakeAuthRepository) SetPasswordByTenant(ctx context.Context, userID uuid.UUID, tenantID, hashedPassword string) error {
	return nil
}

func (f *fakeAuthRepository) SetPasswordAndBumpTokenVersionByTenant(ctx context.Context, userID uuid.UUID, tenantID, hashedPassword string) error {
	if f.user != nil {
		f.user.PasswordHash = hashedPassword
		f.user.TokenVersion++
	}
	return nil
}

func (f *fakeAuthRepository) IncrementTokenVersionByTenant(ctx context.Context, userID uuid.UUID, tenantID string) error {
	return nil
}

func newTestAuthService(repo *fakeAuthRepository) *AuthService {
	pw := NewPasswordService(bcryptTestCost, nil)
	return &AuthService{
		repo:            repo,
		passwordService: pw,
		jwtService:      NewJWTService("test-access-secret", 15*time.Minute, time.Hour, nil),
		logger:          ensureLogger(nil),
	}
}

const bcryptTestCost = 4 // fast for tests

func makeUser(t *testing.T, password string) *model.User {
	t.Helper()
	pw := NewPasswordService(bcryptTestCost, nil)
	hash, err := pw.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	return &model.User{
		ID:           uuid.Must(uuid.NewV7()),
		Email:        "user@acme.test",
		PasswordHash: hash,
		TenantID:     "acme.test",
		Roles:        []string{"Member"},
		IsEnabled:    true,
	}
}

func TestLoginNormalizesEmail(t *testing.T) {
	repo := &fakeAuthRepository{getByEmailErr: model.ErrNotFound}
	svc := newTestAuthService(repo)

	_, _ = svc.Login(context.Background(), model.LoginRequest{
		Email: "  USER@Acme.Test ", Password: "x", TenantID: "acme.test",
	})
	if repo.lastGetByEmail != "user@acme.test" {
		t.Fatalf("lookup email = %q, want normalized %q", repo.lastGetByEmail, "user@acme.test")
	}
}

func TestLoginUnknownUserReturnsGenericError(t *testing.T) {
	repo := &fakeAuthRepository{getByEmailErr: model.ErrNotFound}
	svc := newTestAuthService(repo)

	_, err := svc.Login(context.Background(), model.LoginRequest{
		Email: "nobody@acme.test", Password: "whatever", TenantID: "acme.test",
	})
	if !errors.Is(err, model.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLoginWrongPasswordIncrementsFailedCount(t *testing.T) {
	user := makeUser(t, "Correct1!")
	user.FailedLoginCount = 0
	repo := &fakeAuthRepository{user: user}
	svc := newTestAuthService(repo)

	_, err := svc.Login(context.Background(), model.LoginRequest{
		Email: user.Email, Password: "Wrong1!", TenantID: user.TenantID,
	})
	if !errors.Is(err, model.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if repo.incFailedCalled != 1 {
		t.Fatalf("expected failed-login increment, got %d", repo.incFailedCalled)
	}
	if repo.lockCalled {
		t.Fatal("did not expect lock below threshold")
	}
}

func TestLoginReadsUserFromPrimary(t *testing.T) {
	user := makeUser(t, "Correct1!")
	repo := &fakeAuthRepository{user: user}
	svc := newTestAuthService(repo)

	// Wrong password returns before token generation, so the unit fake (no token
	// service) is sufficient; the gate read at step 1 is what we assert here.
	_, _ = svc.Login(context.Background(), model.LoginRequest{
		Email: user.Email, Password: "Wrong1!", TenantID: user.TenantID,
	})

	// The is_enabled/is_locked gate must read the primary so an admin disable/lock
	// (or a freshly written auto-lock) takes effect without waiting for replica lag.
	if !repo.getByEmailFromPrimaryCalled {
		t.Fatal("Login must read the user from the primary (GetByEmailFromPrimary)")
	}
}

func TestLoginLocksAfterMaxFailedAttempts(t *testing.T) {
	user := makeUser(t, "Correct1!")
	user.FailedLoginCount = MaxFailedLoginAttempts - 1 // next failure trips the lock
	repo := &fakeAuthRepository{user: user}
	svc := newTestAuthService(repo)

	_, err := svc.Login(context.Background(), model.LoginRequest{
		Email: user.Email, Password: "Wrong1!", TenantID: user.TenantID,
	})
	if !errors.Is(err, model.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if !repo.lockCalled {
		t.Fatal("expected account to be locked at threshold")
	}
	if repo.lockedUntilPassed == nil {
		t.Fatal("expected a locked_until to be set")
	}
}

func TestLoginDisabledAccountReturnsGenericError(t *testing.T) {
	user := makeUser(t, "Correct1!")
	user.IsEnabled = false
	repo := &fakeAuthRepository{user: user}
	svc := newTestAuthService(repo)

	// Even with the CORRECT password, a disabled account must fail generically.
	_, err := svc.Login(context.Background(), model.LoginRequest{
		Email: user.Email, Password: "Correct1!", TenantID: user.TenantID,
	})
	if !errors.Is(err, model.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for disabled account, got %v", err)
	}
}

func TestLoginLockedAccountRejectsCorrectPassword(t *testing.T) {
	user := makeUser(t, "Correct1!")
	user.IsLocked = true
	future := time.Now().Add(30 * time.Minute)
	user.LockedUntil = &future
	repo := &fakeAuthRepository{user: user}
	svc := newTestAuthService(repo)

	_, err := svc.Login(context.Background(), model.LoginRequest{
		Email: user.Email, Password: "Correct1!", TenantID: user.TenantID,
	})
	if !errors.Is(err, model.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for locked account, got %v", err)
	}
}

func TestValidateJWTRejectsTokenVersionMismatch(t *testing.T) {
	user := makeUser(t, "Correct1!")
	user.TokenVersion = 3
	repo := &fakeAuthRepository{user: user}
	svc := newTestAuthService(repo)

	// Mint a token stamped with an older version than the user currently has.
	stale := *user
	stale.TokenVersion = 2
	token, err := svc.jwtService.GenerateAccessToken(&stale)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	if _, err := svc.ValidateJWT(context.Background(), token); !errors.Is(err, model.ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked, got %v", err)
	}
}

func TestValidateJWTRejectsDisabledAndLocked(t *testing.T) {
	base := makeUser(t, "Correct1!")
	token, err := NewJWTService("test-access-secret", 15*time.Minute, time.Hour, nil).GenerateAccessToken(base)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	t.Run("disabled", func(t *testing.T) {
		u := *base
		u.IsEnabled = false
		svc := newTestAuthService(&fakeAuthRepository{user: &u})
		if _, err := svc.ValidateJWT(context.Background(), token); !errors.Is(err, model.ErrAccountDisabled) {
			t.Fatalf("expected ErrAccountDisabled, got %v", err)
		}
	})

	t.Run("locked", func(t *testing.T) {
		u := *base
		u.IsLocked = true
		future := time.Now().Add(time.Hour)
		u.LockedUntil = &future
		svc := newTestAuthService(&fakeAuthRepository{user: &u})
		if _, err := svc.ValidateJWT(context.Background(), token); !errors.Is(err, model.ErrAccountLocked) {
			t.Fatalf("expected ErrAccountLocked, got %v", err)
		}
	})
}

func TestValidateJWTReadsUserFromPrimary(t *testing.T) {
	user := makeUser(t, "Correct1!")
	repo := &fakeAuthRepository{user: user}
	svc := newTestAuthService(repo)

	token, err := svc.jwtService.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	if _, err := svc.ValidateJWT(context.Background(), token); err != nil {
		t.Fatalf("validate jwt: %v", err)
	}

	// The revocation / account-status gate must read the primary so token_version,
	// disable and lock writes take effect immediately rather than lagging a replica.
	if !repo.getByIDFromPrimaryCalled {
		t.Fatal("ValidateJWT must read the user from the primary (GetByIDFromPrimary)")
	}
}

func TestChangePasswordRejectsDisabledOrLocked(t *testing.T) {
	// A disabled or locked account must not be able to rotate its own password
	// mid-freeze, even with the correct old password. The status gate runs before
	// password verification, so these return before any token-service call.
	t.Run("disabled", func(t *testing.T) {
		user := makeUser(t, "Correct1!")
		user.IsEnabled = false
		svc := newTestAuthService(&fakeAuthRepository{user: user})

		err := svc.ChangePassword(context.Background(), model.ChangePasswordRequest{
			UserID: user.ID, TenantID: user.TenantID, OldPassword: "Correct1!", NewPassword: "NewStrong1!",
		})
		if !errors.Is(err, model.ErrAccountDisabled) {
			t.Fatalf("expected ErrAccountDisabled, got %v", err)
		}
	})

	t.Run("locked", func(t *testing.T) {
		user := makeUser(t, "Correct1!")
		user.IsLocked = true
		future := time.Now().Add(time.Hour)
		user.LockedUntil = &future
		svc := newTestAuthService(&fakeAuthRepository{user: user})

		err := svc.ChangePassword(context.Background(), model.ChangePasswordRequest{
			UserID: user.ID, TenantID: user.TenantID, OldPassword: "Correct1!", NewPassword: "NewStrong1!",
		})
		if !errors.Is(err, model.ErrAccountLocked) {
			t.Fatalf("expected ErrAccountLocked, got %v", err)
		}
	})
}

func TestValidateJWTRejectsTamperedSignature(t *testing.T) {
	user := makeUser(t, "Correct1!")
	svc := newTestAuthService(&fakeAuthRepository{user: user})

	// Token signed with a different secret must be rejected as invalid.
	other := NewJWTService("a-totally-different-secret", 15*time.Minute, time.Hour, nil)
	token, err := other.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	if _, err := svc.ValidateJWT(context.Background(), token); !errors.Is(err, model.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}
