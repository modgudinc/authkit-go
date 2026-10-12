// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
)

const (
	// secondFactorChallengeTTL is how long a password login waits for its second
	// factor.
	secondFactorChallengeTTL = 5 * time.Minute
	// recoveryCodeCount codes of recoveryCodeChars base32 characters (80 bits) each.
	recoveryCodeCount = 10
	recoveryCodeChars = 16
	// totpCipherV1Prefix tags the stored secret's format, as for SecretService.
	totpCipherV1Prefix = "v1:"

	// Methods recorded for a second factor in logs.
	secondFactorTOTP     = "totp"
	secondFactorRecovery = "recovery_code"

	// Login kinds a challenge finishes.
	pendingLoginTenant  = "login"
	pendingLoginByEmail = "login_by_email"
)

// recoveryEncoding is lowercase base32 without padding, so codes are easy to read
// and type.
var recoveryEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// twoFactorStore is the storage two-factor needs; *repository.Repository
// implements it.
type twoFactorStore interface {
	GetTOTPFactor(ctx context.Context, userID string) (*repository.TOTPFactor, error)
	TwoFactorEnabled(ctx context.Context, userID string) (bool, error)
	SavePendingTOTP(ctx context.Context, userID, secretCiphertext string) error
	ConfirmTOTP(ctx context.Context, userID, secretCiphertext string, step int64, codeHashes []string) error
	ReplaceRecoveryCodes(ctx context.Context, userID string, codeHashes []string) error
	UseTOTPStep(ctx context.Context, userID string, step int64) (bool, error)
	UseRecoveryCode(ctx context.Context, userID, codeHash string) (bool, error)
	DeleteTwoFactor(ctx context.Context, userID string) error
	TwoFactorStatus(ctx context.Context, userID string) (*model.TwoFactorStatus, error)
	InsertSecondFactorChallenge(ctx context.Context, tokenHash, userID string, login []byte, expiresAt time.Time) error
	GetSecondFactorChallenge(ctx context.Context, tokenHash string) (*repository.SecondFactorChallenge, error)
	DeleteSecondFactorChallenge(ctx context.Context, tokenHash string) (bool, error)
	CleanupSecondFactorChallenges(ctx context.Context, now time.Time) (int64, error)
}

// TwoFactorKeys holds what Config.TwoFactorConfig configures: the keys that protect
// authenticator-app secrets and recovery codes, and the issuer name apps show.
type TwoFactorKeys struct {
	aead        cipher.AEAD
	recoveryKey []byte
	issuer      string
}

// NewTwoFactorKeys derives the secret-encryption and recovery-code keys from the
// 32-byte master key with HKDF-SHA256, so the one configured key serves both
// without being used twice.
func NewTwoFactorKeys(masterKey []byte, issuer string) (*TwoFactorKeys, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("two-factor encryption key must be 32 bytes, got %d", len(masterKey))
	}
	encKey, err := hkdf.Key(sha256.New, masterKey, nil, "authkit two-factor secret encryption", 32)
	if err != nil {
		return nil, err
	}
	recoveryKey, err := hkdf.Key(sha256.New, masterKey, nil, "authkit two-factor recovery codes", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &TwoFactorKeys{aead: aead, recoveryKey: recoveryKey, issuer: issuer}, nil
}

// totpAAD binds a stored secret to its user, so a ciphertext copied to another
// user's row does not decrypt.
func totpAAD(userID string) []byte { return []byte("totp\x00" + userID) }

func (k *TwoFactorKeys) seal(userID string, secret []byte) (string, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	return totpCipherV1Prefix + base64.StdEncoding.EncodeToString(k.aead.Seal(nonce, nonce, secret, totpAAD(userID))), nil
}

func (k *TwoFactorKeys) open(userID, ciphertext string) ([]byte, error) {
	rest, ok := strings.CutPrefix(ciphertext, totpCipherV1Prefix)
	if !ok {
		return nil, errors.New("unrecognized authenticator secret format")
	}
	data, err := base64.StdEncoding.DecodeString(rest)
	if err != nil || len(data) < k.aead.NonceSize() {
		return nil, errors.New("malformed authenticator secret")
	}
	secret, err := k.aead.Open(nil, data[:k.aead.NonceSize()], data[k.aead.NonceSize():], totpAAD(userID))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt authenticator secret: %w", err)
	}
	return secret, nil
}

// recoveryHash is the stored form of a normalized recovery code.
func (k *TwoFactorKeys) recoveryHash(code string) string {
	mac := hmac.New(sha256.New, k.recoveryKey)
	mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}

// newRecoveryCodes returns fresh codes to show the person, formatted
// xxxx-xxxx-xxxx-xxxx, and their hashes to store.
func (k *TwoFactorKeys) newRecoveryCodes() (codes, hashes []string, err error) {
	for range recoveryCodeCount {
		raw := make([]byte, recoveryCodeChars*5/8)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, fmt.Errorf("failed to generate recovery code: %w", err)
		}
		code := recoveryEncoding.EncodeToString(raw)
		hashes = append(hashes, k.recoveryHash(code))
		codes = append(codes, code[0:4]+"-"+code[4:8]+"-"+code[8:12]+"-"+code[12:16])
	}
	return codes, hashes, nil
}

// normalizeRecoveryCode strips the separators and spaces people type and checks
// what is left could be a recovery code.
func normalizeRecoveryCode(code string) (string, bool) {
	code = strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(code))
	if len(code) != recoveryCodeChars {
		return "", false
	}
	if _, err := recoveryEncoding.DecodeString(code); err != nil {
		return "", false
	}
	return code, true
}

func challengeHash(challenge string) string {
	sum := sha256.Sum256([]byte(challenge))
	return hex.EncodeToString(sum[:])
}

// pendingLogin is the password login a challenge finishes, stored as JSON.
// TokenVersion is the user's at the password step: a password change or a sign-out
// everywhere since then ends the login.
type pendingLogin struct {
	Kind           string             `json:"kind"`
	TokenVersion   int                `json:"token_version"`
	TenantID       string             `json:"tenant_id,omitempty"`
	InstallationID string             `json:"installation_id,omitempty"`
	Installation   bool               `json:"installation,omitempty"`
	SessionInfo    *model.SessionInfo `json:"session_info,omitempty"`
}

// bound returns p bound to the installation, when the login is.
func (p pendingLogin) bound(binding *model.InstallationBinding) pendingLogin {
	if binding != nil {
		p.Installation, p.InstallationID = true, binding.InstallationID
	}
	return p
}

func (p pendingLogin) binding() *model.InstallationBinding {
	if !p.Installation {
		return nil
	}
	return &model.InstallationBinding{InstallationID: p.InstallationID}
}

// WithTwoFactor makes password logins of users with two-factor on wait for a
// second factor (Config.TwoFactorConfig; migration 000009).
func WithTwoFactor(store *repository.Repository, keys *TwoFactorKeys) AuthOption {
	return func(s *AuthService) {
		s.twoFactorStore = store
		s.twoFactorKeys = keys
	}
}

// requireSecondFactor returns a *model.SecondFactorRequiredError holding a new
// challenge when user has two-factor on, and nil when the login may go ahead.
func (s *AuthService) requireSecondFactor(ctx context.Context, user *model.User, login pendingLogin) error {
	if s.twoFactorStore == nil {
		return nil
	}
	enabled, err := s.twoFactorStore.TwoFactorEnabled(ctx, user.ID)
	if err != nil {
		return sanitizeError(ctx, s.logger, "check two-factor", err)
	}
	if !enabled {
		return nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return sanitizeError(ctx, s.logger, "generate second-factor challenge", err)
	}
	challenge := base64.RawURLEncoding.EncodeToString(raw)
	login.TokenVersion = user.TokenVersion
	encoded, err := json.Marshal(login)
	if err != nil {
		return sanitizeError(ctx, s.logger, "encode pending login", err)
	}
	expiresAt := time.Now().Add(secondFactorChallengeTTL)
	if err := s.twoFactorStore.InsertSecondFactorChallenge(ctx, challengeHash(challenge), user.ID, encoded, expiresAt); err != nil {
		return sanitizeError(ctx, s.logger, "store second-factor challenge", err)
	}
	s.logger.Info(ctx, "Password accepted; waiting for a second factor", "user_id", user.ID)
	return &model.SecondFactorRequiredError{Challenge: challenge, ExpiresAt: expiresAt}
}

// verifySecondFactor checks code for userID: an authenticator-app code (accepted
// once per 30-second step) or an unused recovery code (spent). It returns the
// method used, or model.ErrInvalidSecondFactor.
func (s *AuthService) verifySecondFactor(ctx context.Context, userID, code string) (string, error) {
	code = strings.TrimSpace(code)
	if isTOTPCode(code) {
		factor, err := s.twoFactorStore.GetTOTPFactor(ctx, userID)
		if errors.Is(err, model.ErrNotFound) {
			return "", model.ErrInvalidSecondFactor
		}
		if err != nil {
			return "", err
		}
		if factor.ConfirmedAt == nil {
			return "", model.ErrInvalidSecondFactor
		}
		secret, err := s.twoFactorKeys.open(userID, factor.SecretCiphertext)
		if err != nil {
			return "", err
		}
		step, ok := matchTOTP(secret, code, time.Now())
		if !ok {
			return "", model.ErrInvalidSecondFactor
		}
		used, err := s.twoFactorStore.UseTOTPStep(ctx, userID, step)
		if err != nil {
			return "", err
		}
		if !used {
			return "", model.ErrInvalidSecondFactor // replayed, or turned off meanwhile
		}
		return secondFactorTOTP, nil
	}
	normalized, ok := normalizeRecoveryCode(code)
	if !ok {
		return "", model.ErrInvalidSecondFactor
	}
	used, err := s.twoFactorStore.UseRecoveryCode(ctx, userID, s.twoFactorKeys.recoveryHash(normalized))
	if err != nil {
		return "", err
	}
	if !used {
		return "", model.ErrInvalidSecondFactor
	}
	return secondFactorRecovery, nil
}

// secondFactorFailed counts a wrong second factor toward the account's failed-login
// lockout, as a wrong password does. The count is reset only when a whole sign-in
// succeeds, so knowing the password does not buy more guesses at the code.
func (s *AuthService) secondFactorFailed(ctx context.Context, userID string) {
	s.countFailedAttempt(ctx, userID, "second factor")
}

// countFailedAttempt adds a wrong secret (a second factor, or ChangePassword's old
// password) to the account's failed-login count, locking it at the threshold as a
// wrong login password does. Best-effort: a failed write is logged and counted.
func (s *AuthService) countFailedAttempt(ctx context.Context, userID, what string) {
	count, locked, err := s.repo.RegisterFailedLogin(ctx, userID, MaxFailedLoginAttempts, LockDuration)
	switch {
	case err != nil:
		s.logger.Error(ctx, "Failed to record failed "+what, "error", err.Error())
		incMetric(s.metrics, metrics.CounterBestEffortWriteFailure, "op", "register_failed_login")
	case locked:
		s.logger.Warn(ctx, "Account locked after max failed attempts", "user_id", userID, "failed_attempts", count)
		incMetric(s.metrics, metrics.CounterAccountLockout)
	default:
		s.logger.Info(ctx, "Failed "+what+" recorded", "user_id", userID, "failed_attempts", count)
	}
}

// completeSecondFactor finishes a password login that waited for its second
// factor.
func (s *AuthService) completeSecondFactor(ctx context.Context, req model.CompleteSecondFactorRequest) (*model.InstallationLoginResponse, error) {
	if s.twoFactorStore == nil {
		return nil, model.ErrTwoFactorNotConfigured
	}
	challenge := strings.TrimSpace(req.Challenge)
	if challenge == "" {
		return nil, model.ErrInvalidCredentials
	}
	hash := challengeHash(challenge)
	pending, err := s.twoFactorStore.GetSecondFactorChallenge(ctx, hash)
	if errors.Is(err, model.ErrNotFound) {
		return nil, model.ErrInvalidCredentials
	}
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "load second-factor challenge", err)
	}
	if time.Now().After(pending.ExpiresAt) {
		if _, err := s.twoFactorStore.DeleteSecondFactorChallenge(ctx, hash); err != nil {
			s.logger.Warn(ctx, "Failed to delete expired second-factor challenge", "error", err.Error())
		}
		return nil, model.ErrInvalidCredentials
	}
	var login pendingLogin
	if err := json.Unmarshal(pending.Login, &login); err != nil {
		return nil, sanitizeError(ctx, s.logger, "decode pending login", err)
	}

	// Throttle code guesses per account, like the password step.
	if err := checkRateLimit(ctx, s.rateLimiter, s.metrics, s.logger, "second_factor:"+pending.UserID); err != nil {
		return nil, err
	}

	attempt := signIn{method: model.SignInMethodPassword, tenantID: login.TenantID, installation: login.binding(), info: login.SessionInfo}
	// Read from the PRIMARY: a lock from wrong codes must stop the next one.
	user, err := s.repo.GetByIDFromPrimary(ctx, pending.UserID)
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "load user", err)
	}
	if err := accountGate(user); err != nil {
		s.logger.Warn(ctx, "Second factor refused: account not active", "user_id", user.ID, "error", err.Error())
		s.recordSignInFailure(ctx, attempt, user.ID, signInFailureReason(err))
		return nil, err
	}
	if user.TokenVersion != login.TokenVersion {
		s.logger.Warn(ctx, "Second factor refused: password changed or signed out everywhere since the password step", "user_id", user.ID)
		if _, err := s.twoFactorStore.DeleteSecondFactorChallenge(ctx, hash); err != nil {
			s.logger.Warn(ctx, "Failed to delete stale second-factor challenge", "error", err.Error())
		}
		return nil, model.ErrInvalidCredentials
	}

	method, err := s.verifySecondFactor(ctx, user.ID, req.Code)
	if errors.Is(err, model.ErrInvalidSecondFactor) {
		s.logger.Warn(ctx, "Second factor refused", "user_id", user.ID)
		s.secondFactorFailed(ctx, user.ID)
		incMetric(s.metrics, metrics.CounterLoginFailure, "reason", model.SignInFailureBadSecondFactor)
		s.recordSignInFailure(ctx, attempt, user.ID, model.SignInFailureBadSecondFactor)
		return nil, err
	}
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "verify second factor", err)
	}

	// Only one call finishes a login, even with two good codes.
	finished, err := s.twoFactorStore.DeleteSecondFactorChallenge(ctx, hash)
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "consume second-factor challenge", err)
	}
	if !finished {
		return nil, model.ErrInvalidCredentials
	}
	s.logger.Info(ctx, "Second factor accepted", "user_id", user.ID, "method", method)
	s.passwordAccepted(ctx, user)

	var resp *model.LoginResponse
	var session *model.Session
	switch login.Kind {
	case pendingLoginTenant:
		resp, session, err = s.finishLogin(ctx, user, login.TenantID, login.SessionInfo, login.binding(), attempt)
	case pendingLoginByEmail:
		resp, session, err = s.finishLoginByEmail(ctx, user, login.TenantID, login.SessionInfo, login.binding(), attempt)
	default:
		err = fmt.Errorf("unknown pending login kind %q", login.Kind)
	}
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "finish login", err)
	}
	return &model.InstallationLoginResponse{LoginResponse: *resp, Session: session}, nil
}

// TwoFactorService sets up and checks authenticator-app (TOTP) two-factor and its
// recovery codes, and finishes password logins that wait for a second factor.
// Requires Config.TwoFactorConfig and migration 000009.
type TwoFactorService struct {
	auth    *AuthService
	store   twoFactorStore
	keys    *TwoFactorKeys
	logger  logger.Logger
	metrics metrics.Metrics
}

// NewTwoFactorService creates a TwoFactorService. auth finishes logins; keys is nil
// when two-factor is not configured, and every call then returns
// ErrTwoFactorNotConfigured.
func NewTwoFactorService(repo *repository.Repository, auth *AuthService, keys *TwoFactorKeys, logger logger.Logger, m metrics.Metrics) *TwoFactorService {
	return &TwoFactorService{auth: auth, store: repo, keys: keys, logger: ensureLogger(logger), metrics: m}
}

func (s *TwoFactorService) configured(userID string) error {
	if s.keys == nil {
		return model.ErrTwoFactorNotConfigured
	}
	if userID == "" {
		return fmt.Errorf("user id is required: %w", model.ErrInvalidInput)
	}
	return nil
}

// EnrollTOTP starts setting up an authenticator app for a signed-in user: it makes
// a new secret, stores it encrypted and not yet on, and returns it for the person
// to add to their app. It replaces an earlier enrollment that was never confirmed.
// Returns ErrTwoFactorAlreadyEnabled when the user already has an app on, and
// ErrNotFound for an unknown user.
func (s *TwoFactorService) EnrollTOTP(ctx context.Context, userID string) (*model.TOTPEnrollment, error) {
	if err := s.configured(userID); err != nil {
		return nil, err
	}
	user, err := s.auth.repo.GetByIDFromPrimary(ctx, userID)
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "load user", err)
	}
	secret := make([]byte, totpSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return nil, sanitizeError(ctx, s.logger, "generate authenticator secret", err)
	}
	sealed, err := s.keys.seal(userID, secret)
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "encrypt authenticator secret", err)
	}
	if err := s.store.SavePendingTOTP(ctx, userID, sealed); err != nil {
		return nil, sanitizeError(ctx, s.logger, "store authenticator secret", err)
	}
	s.logger.Info(ctx, "Authenticator app enrollment started", "user_id", userID)
	return &model.TOTPEnrollment{
		Secret: totpEncoding.EncodeToString(secret),
		URI:    totpURI(s.keys.issuer, user.Email, secret),
	}, nil
}

// ConfirmTOTP turns two-factor on once the person enters a code from the app they
// just set up, and returns their recovery codes. Show the codes once: only their
// hashes are kept. From then on their password logins need a second factor.
// Returns ErrInvalidSecondFactor for a wrong code, ErrNotFound when no enrollment
// is waiting, and ErrTwoFactorAlreadyEnabled when it is already on.
func (s *TwoFactorService) ConfirmTOTP(ctx context.Context, userID, code string) ([]string, error) {
	ctx = signingIn(ctx)
	if err := s.configured(userID); err != nil {
		return nil, err
	}
	factor, err := s.store.GetTOTPFactor(ctx, userID)
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "load authenticator app", err)
	}
	if factor.ConfirmedAt != nil {
		return nil, model.ErrTwoFactorAlreadyEnabled
	}
	secret, err := s.keys.open(userID, factor.SecretCiphertext)
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "decrypt authenticator secret", err)
	}
	code = strings.TrimSpace(code)
	step, ok := matchTOTP(secret, code, time.Now())
	if !isTOTPCode(code) || !ok {
		return nil, model.ErrInvalidSecondFactor
	}
	codes, hashes, err := s.keys.newRecoveryCodes()
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "generate recovery codes", err)
	}
	if err := s.store.ConfirmTOTP(ctx, userID, factor.SecretCiphertext, step, hashes); err != nil {
		return nil, sanitizeError(ctx, s.logger, "turn on two-factor", err)
	}
	s.logger.Info(ctx, "Two-factor turned on", "user_id", userID)
	return codes, nil
}

// Verify checks a code from the user's authenticator app, or one of their recovery
// codes (which it spends), for a signed-in person: before turning two-factor off or
// another sensitive change. A wrong code counts toward the account's failed-login
// lockout, and a locked or disabled account is refused before any code is checked,
// so the lockout stops guessing here as it does at sign-in. Returns
// ErrInvalidSecondFactor for a wrong or reused code, ErrAccountLocked or
// ErrAccountDisabled, and ErrNotFound for an unknown user or one with two-factor off.
func (s *TwoFactorService) Verify(ctx context.Context, userID, code string) error {
	ctx = signingIn(ctx)
	if err := s.configured(userID); err != nil {
		return err
	}
	// Read from the PRIMARY: a lock from wrong codes must stop the next one.
	user, err := s.auth.repo.GetByIDFromPrimary(ctx, userID)
	if err != nil {
		return sanitizeError(ctx, s.logger, "load user", err)
	}
	if err := accountGate(user); err != nil {
		s.logger.Warn(ctx, "Second factor check refused: account not active", "user_id", userID, "error", err.Error())
		return err
	}
	enabled, err := s.store.TwoFactorEnabled(ctx, userID)
	if err != nil {
		return sanitizeError(ctx, s.logger, "check two-factor", err)
	}
	if !enabled {
		return fmt.Errorf("two-factor is not on: %w", model.ErrNotFound)
	}
	_, err = s.auth.verifySecondFactor(ctx, userID, code)
	if errors.Is(err, model.ErrInvalidSecondFactor) {
		s.auth.secondFactorFailed(ctx, userID)
		return err
	}
	return sanitizeError(ctx, s.logger, "verify second factor", err)
}

// Disable turns two-factor off for a user: it deletes their authenticator secret,
// recovery codes and any login waiting for a code. Confirm it is the person first,
// with Verify or a fresh password. Returns ErrNotFound when they have none.
func (s *TwoFactorService) Disable(ctx context.Context, userID string) error {
	if err := s.configured(userID); err != nil {
		return err
	}
	if err := s.store.DeleteTwoFactor(ctx, userID); err != nil {
		return sanitizeError(ctx, s.logger, "turn off two-factor", err)
	}
	s.logger.Info(ctx, "Two-factor turned off", "user_id", userID)
	return nil
}

// RegenerateRecoveryCodes replaces a user's recovery codes with new ones and
// returns them; the old ones stop working. Returns ErrNotFound when two-factor is
// off.
func (s *TwoFactorService) RegenerateRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	if err := s.configured(userID); err != nil {
		return nil, err
	}
	codes, hashes, err := s.keys.newRecoveryCodes()
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "generate recovery codes", err)
	}
	if err := s.store.ReplaceRecoveryCodes(ctx, userID, hashes); err != nil {
		return nil, sanitizeError(ctx, s.logger, "replace recovery codes", err)
	}
	s.logger.Info(ctx, "Recovery codes replaced", "user_id", userID)
	return codes, nil
}

// Status reports whether a user has two-factor on and how many recovery codes they
// have left.
func (s *TwoFactorService) Status(ctx context.Context, userID string) (*model.TwoFactorStatus, error) {
	if err := s.configured(userID); err != nil {
		return nil, err
	}
	status, err := s.store.TwoFactorStatus(ctx, userID)
	return status, sanitizeError(ctx, s.logger, "load two-factor status", err)
}

// CompleteSecondFactor finishes a password login that returned
// ErrSecondFactorRequired, with a code from the person's authenticator app or a
// recovery code. On success it does what the login would have done (workspace
// selection, the session, the access token) and returns the response, with Session
// set when the login was bound to an installation. A wrong code returns
// ErrInvalidSecondFactor and counts toward the failed-login lockout; the challenge
// stays usable until it expires. An unknown, expired or finished challenge returns
// ErrInvalidCredentials: sign in again.
func (s *TwoFactorService) CompleteSecondFactor(ctx context.Context, req model.CompleteSecondFactorRequest) (*model.InstallationLoginResponse, error) {
	ctx = signingIn(ctx)
	if s.keys == nil {
		return nil, model.ErrTwoFactorNotConfigured
	}
	return s.auth.completeSecondFactor(ctx, req)
}

// CleanupExpired deletes logins that waited for a second factor until they
// expired, and returns how many. Run it periodically.
func (s *TwoFactorService) CleanupExpired(ctx context.Context) (int64, error) {
	if s.keys == nil {
		return 0, model.ErrTwoFactorNotConfigured
	}
	n, err := s.store.CleanupSecondFactorChallenges(ctx, time.Now())
	return n, sanitizeError(ctx, s.logger, "cleanup second-factor challenges", err)
}
