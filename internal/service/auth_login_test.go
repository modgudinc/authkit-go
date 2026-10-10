// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/model"
)

// testTenantID is the workspace used by the auth unit tests; makeMembership grants
// the test user an active membership in it.
const testTenantID = "acme.test"

// fakeAuthRepository is an in-memory authRepository for unit-testing the
// security-critical AuthService logic (lockout, enumeration, revocation checks)
// without a database. It serves a single user and (optionally) a single membership.
type fakeAuthRepository struct {
	user       *model.User
	membership *model.Membership

	getByEmailErr    error
	getByIDErr       error
	getMembershipErr error

	lastGetByEmail              string
	lockCalled                  bool
	unlockCalled                bool
	incFailedCalled             int
	updateLastLogin             int
	lockedUntilPassed           *time.Time
	getByIDFromPrimaryCalled    bool
	getByEmailFromPrimaryCalled bool
	getMembershipCalled         bool
}

// GetByEmailFromPrimary serves the global identity lookup; the primary/replica split
// is a repository concern, so the in-memory fake serves it from the single record.
func (f *fakeAuthRepository) GetByEmailFromPrimary(ctx context.Context, email string) (*model.User, error) {
	f.getByEmailFromPrimaryCalled = true
	f.lastGetByEmail = email
	if f.getByEmailErr != nil {
		return nil, f.getByEmailErr
	}
	return f.user, nil
}

// GetByIDFromPrimary mirrors the identity-by-id lookup; it records that it was called
// so a test can assert the security gate uses the primary.
func (f *fakeAuthRepository) GetByIDFromPrimary(ctx context.Context, userID string) (*model.User, error) {
	f.getByIDFromPrimaryCalled = true
	if f.getByIDErr != nil {
		return nil, f.getByIDErr
	}
	return f.user, nil
}

func (f *fakeAuthRepository) AutoUnlock(ctx context.Context, userID string) error {
	f.unlockCalled = true
	if f.user != nil {
		f.user.IsLocked = false
		f.user.FailedLoginCount = 0
	}
	return nil
}

func (f *fakeAuthRepository) RegisterFailedLogin(ctx context.Context, userID string, maxAttempts int, lockDuration time.Duration) (int, bool, error) {
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

func (f *fakeAuthRepository) UpdateLastLogin(ctx context.Context, userID string) error {
	f.updateLastLogin++
	return nil
}

func (f *fakeAuthRepository) SetPasswordAndBumpTokenVersion(ctx context.Context, userID, hashedPassword string) error {
	if f.user != nil {
		f.user.PasswordHash = hashedPassword
		f.user.TokenVersion++
	}
	return nil
}

func (f *fakeAuthRepository) IncrementTokenVersion(ctx context.Context, userID string) error {
	if f.user != nil {
		f.user.TokenVersion++
	}
	return nil
}

func (f *fakeAuthRepository) GetMembershipFromPrimary(ctx context.Context, userID, tenantID string) (*model.Membership, error) {
	f.getMembershipCalled = true
	if f.getMembershipErr != nil {
		return nil, f.getMembershipErr
	}
	if f.membership == nil {
		return nil, model.ErrNotFound
	}
	return f.membership, nil
}

func (f *fakeAuthRepository) ListMembershipsByUser(ctx context.Context, userID string) ([]*model.Membership, error) {
	if f.membership == nil {
		return nil, nil
	}
	return []*model.Membership{f.membership}, nil
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
		ID:           uuid.Must(uuid.NewV7()).String(),
		Email:        "user@acme.test",
		PasswordHash: hash,
		IsEnabled:    true,
	}
}

// makeMembership returns an active membership for userID in testTenantID. Its
// TokenVersion is 0 so a token minted from it (and from a TokenVersion-0 user)
// validates cleanly.
func makeMembership(userID string) *model.Membership {
	return &model.Membership{
		UserID:   userID,
		TenantID: testTenantID,
		Roles:    []string{"Member"},
		Status:   model.MembershipActive,
	}
}

func TestLoginNormalizesEmail(t *testing.T) {
	repo := &fakeAuthRepository{getByEmailErr: model.ErrNotFound}
	svc := newTestAuthService(repo)

	_, _ = svc.Login(context.Background(), model.LoginRequest{
		Email: "  USER@Acme.Test ", Password: "x", TenantID: testTenantID,
	})
	if repo.lastGetByEmail != "user@acme.test" {
		t.Fatalf("lookup email = %q, want normalized %q", repo.lastGetByEmail, "user@acme.test")
	}
}

func TestLoginUnknownUserReturnsGenericError(t *testing.T) {
	repo := &fakeAuthRepository{getByEmailErr: model.ErrNotFound}
	svc := newTestAuthService(repo)

	_, err := svc.Login(context.Background(), model.LoginRequest{
		Email: "nobody@acme.test", Password: "whatever", TenantID: testTenantID,
	})
	if !errors.Is(err, model.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

// A user that cannot be read (database down, migration missing) is an internal
// error, not a wrong password, so the application answers 500 instead of telling the
// person their credentials are wrong. The driver's error stays in the log.
func TestLoginStorageFailureIsInternalError(t *testing.T) {
	repo := &fakeAuthRepository{getByEmailErr: errors.New("failed to get user by email: dial tcp 10.0.0.5:5432: connection refused")}
	svc := newTestAuthService(repo)
	ctx := context.Background()

	_, loginErr := svc.Login(ctx, model.LoginRequest{Email: "user@acme.test", Password: "whatever", TenantID: testTenantID})
	_, byEmailErr := svc.LoginByEmail(ctx, model.LoginByEmailRequest{Email: "user@acme.test", Password: "whatever"})
	for name, err := range map[string]error{"Login": loginErr, "LoginByEmail": byEmailErr} {
		if !errors.Is(err, model.ErrInternal) || errors.Is(err, model.ErrInvalidCredentials) {
			t.Fatalf("%s: expected ErrInternal and not ErrInvalidCredentials, got %v", name, err)
		}
		if strings.Contains(err.Error(), "10.0.0.5") {
			t.Fatalf("%s: the driver error reached the caller: %v", name, err)
		}
	}
}

func TestLoginWrongPasswordIncrementsFailedCount(t *testing.T) {
	user := makeUser(t, "Correct1!")
	user.FailedLoginCount = 0
	repo := &fakeAuthRepository{user: user, membership: makeMembership(user.ID)}
	svc := newTestAuthService(repo)

	_, err := svc.Login(context.Background(), model.LoginRequest{
		Email: user.Email, Password: "Wrong1!", TenantID: testTenantID,
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
	repo := &fakeAuthRepository{user: user, membership: makeMembership(user.ID)}
	svc := newTestAuthService(repo)

	// Wrong password returns before token generation, so the unit fake (no token
	// service) is sufficient; the gate read at step 1 is what we assert here.
	_, _ = svc.Login(context.Background(), model.LoginRequest{
		Email: user.Email, Password: "Wrong1!", TenantID: testTenantID,
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
	repo := &fakeAuthRepository{user: user, membership: makeMembership(user.ID)}
	svc := newTestAuthService(repo)

	_, err := svc.Login(context.Background(), model.LoginRequest{
		Email: user.Email, Password: "Wrong1!", TenantID: testTenantID,
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
	repo := &fakeAuthRepository{user: user, membership: makeMembership(user.ID)}
	svc := newTestAuthService(repo)

	// Even with the CORRECT password, a disabled account must fail generically.
	_, err := svc.Login(context.Background(), model.LoginRequest{
		Email: user.Email, Password: "Correct1!", TenantID: testTenantID,
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
	repo := &fakeAuthRepository{user: user, membership: makeMembership(user.ID)}
	svc := newTestAuthService(repo)

	_, err := svc.Login(context.Background(), model.LoginRequest{
		Email: user.Email, Password: "Correct1!", TenantID: testTenantID,
	})
	if !errors.Is(err, model.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for locked account, got %v", err)
	}
}

func TestLoginNoActiveMembershipRejected(t *testing.T) {
	// Valid credentials but no membership in the requested workspace must fail with
	// ErrNoActiveMembership (after a successful password verify).
	user := makeUser(t, "Correct1!")
	repo := &fakeAuthRepository{user: user} // membership nil -> not a member
	svc := newTestAuthService(repo)

	_, err := svc.Login(context.Background(), model.LoginRequest{
		Email: user.Email, Password: "Correct1!", TenantID: testTenantID,
	})
	if !errors.Is(err, model.ErrNoActiveMembership) {
		t.Fatalf("expected ErrNoActiveMembership, got %v", err)
	}
}

func TestValidateJWTRejectsTokenVersionMismatch(t *testing.T) {
	user := makeUser(t, "Correct1!")
	user.TokenVersion = 3
	membership := makeMembership(user.ID)
	repo := &fakeAuthRepository{user: user, membership: membership}
	svc := newTestAuthService(repo)

	// Mint a token stamped with an older identity version than the user currently has.
	stale := *user
	stale.TokenVersion = 2
	token, err := svc.jwtService.GenerateAccessToken(&stale, membership)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	if _, err := svc.ValidateJWT(context.Background(), token); !errors.Is(err, model.ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked, got %v", err)
	}
}

func TestValidateJWTRejectsMembershipTokenVersionMismatch(t *testing.T) {
	// A role change / revoke bumps the membership token_version; an access token
	// stamped with the old membership version must be rejected as revoked.
	user := makeUser(t, "Correct1!")
	membership := makeMembership(user.ID)
	membership.TokenVersion = 4
	repo := &fakeAuthRepository{user: user, membership: membership}
	svc := newTestAuthService(repo)

	staleMembership := *membership
	staleMembership.TokenVersion = 3
	token, err := svc.jwtService.GenerateAccessToken(user, &staleMembership)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	if _, err := svc.ValidateJWT(context.Background(), token); !errors.Is(err, model.ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked for membership version mismatch, got %v", err)
	}
}

func TestValidateJWTRejectsRemovedMembership(t *testing.T) {
	// A token whose membership has been removed (or suspended) must be rejected.
	user := makeUser(t, "Correct1!")
	membership := makeMembership(user.ID)
	token, err := NewJWTService("test-access-secret", 15*time.Minute, time.Hour, nil).GenerateAccessToken(user, membership)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	// membership nil -> GetMembershipFromPrimary returns not-found.
	svc := newTestAuthService(&fakeAuthRepository{user: user})
	if _, err := svc.ValidateJWT(context.Background(), token); !errors.Is(err, model.ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked for removed membership, got %v", err)
	}

	// suspended membership -> also revoked.
	suspended := makeMembership(user.ID)
	suspended.Status = model.MembershipSuspended
	svc = newTestAuthService(&fakeAuthRepository{user: user, membership: suspended})
	if _, err := svc.ValidateJWT(context.Background(), token); !errors.Is(err, model.ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked for suspended membership, got %v", err)
	}
}

func TestValidateJWTRejectsDisabledAndLocked(t *testing.T) {
	base := makeUser(t, "Correct1!")
	membership := makeMembership(base.ID)
	token, err := NewJWTService("test-access-secret", 15*time.Minute, time.Hour, nil).GenerateAccessToken(base, membership)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	t.Run("disabled", func(t *testing.T) {
		u := *base
		u.IsEnabled = false
		svc := newTestAuthService(&fakeAuthRepository{user: &u, membership: membership})
		if _, err := svc.ValidateJWT(context.Background(), token); !errors.Is(err, model.ErrAccountDisabled) {
			t.Fatalf("expected ErrAccountDisabled, got %v", err)
		}
	})

	t.Run("locked", func(t *testing.T) {
		u := *base
		u.IsLocked = true
		future := time.Now().Add(time.Hour)
		u.LockedUntil = &future
		svc := newTestAuthService(&fakeAuthRepository{user: &u, membership: membership})
		if _, err := svc.ValidateJWT(context.Background(), token); !errors.Is(err, model.ErrAccountLocked) {
			t.Fatalf("expected ErrAccountLocked, got %v", err)
		}
	})
}

func TestValidateJWTReadsUserFromPrimary(t *testing.T) {
	user := makeUser(t, "Correct1!")
	membership := makeMembership(user.ID)
	repo := &fakeAuthRepository{user: user, membership: membership}
	svc := newTestAuthService(repo)

	token, err := svc.jwtService.GenerateAccessToken(user, membership)
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
			UserID: user.ID, OldPassword: "Correct1!", NewPassword: "NewStrong1!",
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
			UserID: user.ID, OldPassword: "Correct1!", NewPassword: "NewStrong1!",
		})
		if !errors.Is(err, model.ErrAccountLocked) {
			t.Fatalf("expected ErrAccountLocked, got %v", err)
		}
	})
}

func TestValidateJWTRejectsTamperedSignature(t *testing.T) {
	user := makeUser(t, "Correct1!")
	membership := makeMembership(user.ID)
	svc := newTestAuthService(&fakeAuthRepository{user: user, membership: membership})

	// Token signed with a different secret must be rejected as invalid.
	other := NewJWTService("a-totally-different-secret", 15*time.Minute, time.Hour, nil)
	token, err := other.GenerateAccessToken(user, membership)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	if _, err := svc.ValidateJWT(context.Background(), token); !errors.Is(err, model.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

// fakeRateLimiter records the keys it is asked about and returns a configured verdict.
type fakeRateLimiter struct {
	allow bool
	err   error
	keys  []string
}

func (f *fakeRateLimiter) Allow(_ context.Context, key string) (bool, error) {
	f.keys = append(f.keys, key)
	return f.allow, f.err
}

func TestLoginRateLimited(t *testing.T) {
	user := makeUser(t, "Correct1!")
	rl := &fakeRateLimiter{allow: false}
	svc := newTestAuthService(&fakeAuthRepository{user: user, membership: makeMembership(user.ID)})
	svc.rateLimiter = rl

	_, err := svc.Login(context.Background(), model.LoginRequest{
		Email: user.Email, Password: "Correct1!", TenantID: testTenantID,
		SessionInfo: &model.SessionInfo{IPAddress: "203.0.113.5"},
	})
	if !errors.Is(err, model.ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
	// Keyed by tenant + client IP, and checked before any password work.
	if want := "login:" + testTenantID + ":203.0.113.5"; len(rl.keys) != 1 || rl.keys[0] != want {
		t.Fatalf("rate-limit key = %v, want [%q]", rl.keys, want)
	}
}

func TestLoginRateLimiterFailsOpen(t *testing.T) {
	user := makeUser(t, "Correct1!")
	svc := newTestAuthService(&fakeAuthRepository{user: user, membership: makeMembership(user.ID)})
	svc.rateLimiter = &fakeRateLimiter{allow: false, err: errors.New("limiter backend down")}

	// A limiter error must fail OPEN: the request proceeds (and here fails on the
	// wrong password) rather than being rejected as rate-limited.
	_, err := svc.Login(context.Background(), model.LoginRequest{
		Email: user.Email, Password: "WrongPassword1!", TenantID: testTenantID,
	})
	if errors.Is(err, model.ErrRateLimited) {
		t.Fatal("a limiter error must fail open, not return ErrRateLimited")
	}
	if !errors.Is(err, model.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials (proceeded past the limiter), got %v", err)
	}
}
