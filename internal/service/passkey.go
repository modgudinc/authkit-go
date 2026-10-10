// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
)

const (
	// maxRPIDLength bounds a relying party ID, which is a domain name.
	maxRPIDLength = 253
	// maxCredentialIDBytes is the longest credential ID WebAuthn lets a relying
	// party accept.
	maxCredentialIDBytes = 1023
	// maxTransports and maxTransportLength bound the transport hints, which the
	// browser reports and nothing signs.
	maxTransports      = 16
	maxTransportLength = 32
	// maxPasskeyNameRunes bounds a passkey's label (a VARCHAR(255) column).
	maxPasskeyNameRunes = 255
	// aaguidBytes is the size of an authenticator's AAGUID.
	aaguidBytes = 16
)

// PasskeyService stores WebAuthn credentials (passkeys and security keys) and the
// user handles they carry. It does not run WebAuthn ceremonies: the application
// verifies them with its own WebAuthn library (github.com/go-webauthn/webauthn)
// and keeps the results here. Requires migration 000008.
type PasskeyService struct {
	repo    *repository.Repository
	logger  logger.Logger
	metrics metrics.Metrics
}

// NewPasskeyService creates a new PasskeyService.
func NewPasskeyService(repo *repository.Repository, logger logger.Logger, m metrics.Metrics) *PasskeyService {
	return &PasskeyService{repo: repo, logger: ensureLogger(logger), metrics: m}
}

// normalizeRPID lowercases and trims a relying party ID and checks it is a domain
// name: 1 to 253 of [a-z0-9.-], without a leading, trailing or doubled dot.
func normalizeRPID(rpID string) (string, error) {
	rpID = strings.ToLower(strings.TrimSpace(rpID))
	if rpID == "" || len(rpID) > maxRPIDLength || strings.HasPrefix(rpID, ".") || strings.HasSuffix(rpID, ".") || strings.Contains(rpID, "..") {
		return "", fmt.Errorf("relying party ID must be a domain name: %w", model.ErrInvalidInput)
	}
	for _, ch := range rpID {
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '.' && ch != '-' {
			return "", fmt.Errorf("relying party ID must be a domain name: %w", model.ErrInvalidInput)
		}
	}
	return rpID, nil
}

func checkCredentialID(id []byte) error {
	if len(id) == 0 || len(id) > maxCredentialIDBytes {
		return fmt.Errorf("credential ID must be 1 to %d bytes: %w", maxCredentialIDBytes, model.ErrInvalidInput)
	}
	return nil
}

// passkeyKey validates and normalizes the (user, RP ID) pair most calls take.
func passkeyKey(userID, rpID string) (string, error) {
	if userID == "" {
		return "", fmt.Errorf("user id is required: %w", model.ErrInvalidInput)
	}
	return normalizeRPID(rpID)
}

// passkeyName trims a passkey's label and checks it can be stored.
func passkeyName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if strings.ContainsRune(name, 0) || !utf8.ValidString(name) {
		return "", fmt.Errorf("passkey name must be UTF-8 text: %w", model.ErrInvalidInput)
	}
	if utf8.RuneCountInString(name) > maxPasskeyNameRunes {
		return "", fmt.Errorf("passkey name is longer than %d characters: %w", maxPasskeyNameRunes, model.ErrValueTooLong)
	}
	return name, nil
}

func checkTransports(transports []string) error {
	if len(transports) > maxTransports {
		return fmt.Errorf("at most %d transports: %w", maxTransports, model.ErrInvalidInput)
	}
	for _, t := range transports {
		if t == "" || len(t) > maxTransportLength {
			return fmt.Errorf("transport must be 1 to %d characters: %w", maxTransportLength, model.ErrInvalidInput)
		}
		for _, ch := range t {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' && ch != '_' {
				return fmt.Errorf("transport may contain only lowercase letters, digits, '-' and '_': %w", model.ErrInvalidInput)
			}
		}
	}
	return nil
}

// optionalName normalizes an attestation type or format, which may be empty.
func optionalName(name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", nil
	}
	return normalizeName(name)
}

// User returns what a WebAuthn ceremony at rpID needs to know about a user: the
// user, their WebAuthn user handle there (created on first use), and their passkeys
// there. Use it to register a passkey for a signed-in user, and for a sign-in that
// names the user first. It reads the primary, so a removed passkey is gone at once.
// Returns ErrNotFound for an unknown user; it does not check account status, which
// VerifiedLoginService.OpenSession does.
func (s *PasskeyService) User(ctx context.Context, userID, rpID string) (*model.PasskeyUser, error) {
	rpID, err := passkeyKey(userID, rpID)
	if err != nil {
		return nil, err
	}
	user, err := s.repo.GetByIDFromPrimary(ctx, userID)
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "load passkey user", err)
	}
	handle, err := s.repo.PasskeyUserHandle(ctx, rpID, userID)
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "load passkey user handle", err)
	}
	return s.passkeyUser(ctx, rpID, user, handle)
}

// UserByHandle is User for the user that a discoverable sign-in's user handle
// names at rpID. Returns ErrNotFound when no user has the handle there.
func (s *PasskeyService) UserByHandle(ctx context.Context, rpID string, userHandle []byte) (*model.PasskeyUser, error) {
	rpID, err := normalizeRPID(rpID)
	if err != nil {
		return nil, err
	}
	if len(userHandle) == 0 {
		return nil, fmt.Errorf("user handle is required: %w", model.ErrInvalidInput)
	}
	userID, err := s.repo.PasskeyUserIDByHandle(ctx, rpID, userHandle)
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "find passkey user", err)
	}
	user, err := s.repo.GetByIDFromPrimary(ctx, userID)
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "load passkey user", err)
	}
	return s.passkeyUser(ctx, rpID, user, userHandle)
}

func (s *PasskeyService) passkeyUser(ctx context.Context, rpID string, user *model.User, handle []byte) (*model.PasskeyUser, error) {
	passkeys, err := s.repo.ListPasskeysFromPrimary(ctx, rpID, user.ID)
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "list passkeys", err)
	}
	return &model.PasskeyUser{User: user, UserHandle: handle, Passkeys: passkeys}, nil
}

// Register stores a passkey the application verified in a WebAuthn registration
// ceremony for req.UserID, whose options used the user's handle from User. It
// returns ErrPasskeyAlreadyRegistered when the credential ID is already registered
// at the RP ID (to anyone), and ErrNotFound when the user has no handle there:
// call User before the ceremony.
func (s *PasskeyService) Register(ctx context.Context, req model.RegisterPasskeyRequest) (*model.Passkey, error) {
	rpID, err := passkeyKey(req.UserID, req.RPID)
	if err != nil {
		return nil, err
	}
	if err := checkCredentialID(req.CredentialID); err != nil {
		return nil, err
	}
	if len(req.PublicKey) == 0 {
		return nil, fmt.Errorf("public key is required: %w", model.ErrInvalidInput)
	}
	if len(req.AAGUID) != 0 && len(req.AAGUID) != aaguidBytes {
		return nil, fmt.Errorf("AAGUID must be empty or %d bytes: %w", aaguidBytes, model.ErrInvalidInput)
	}
	if req.BackupState && !req.BackupEligible {
		return nil, fmt.Errorf("a passkey that is not backup eligible cannot be backed up: %w", model.ErrInvalidInput)
	}
	if err := checkTransports(req.Transports); err != nil {
		return nil, err
	}
	name, err := passkeyName(req.Name)
	if err != nil {
		return nil, err
	}
	attestationType, err := optionalName(req.AttestationType)
	if err != nil {
		return nil, err
	}
	attestationFormat, err := optionalName(req.AttestationFormat)
	if err != nil {
		return nil, err
	}

	passkey := &model.Passkey{
		RPID: rpID, CredentialID: req.CredentialID, UserID: req.UserID, Name: name,
		PublicKey: req.PublicKey, SignCount: req.SignCount, Transports: req.Transports,
		UserVerified: req.UserVerified, BackupEligible: req.BackupEligible, BackupState: req.BackupState,
		AAGUID: req.AAGUID, AttestationType: attestationType, AttestationFormat: attestationFormat,
		AttestationObject: req.AttestationObject, AttestationClientDataJSON: req.AttestationClientDataJSON,
	}
	if err := s.repo.InsertPasskey(ctx, passkey); err != nil {
		return nil, sanitizeError(ctx, s.logger, "register passkey", err)
	}
	s.logger.Info(ctx, "Passkey registered", "user_id", req.UserID, "rp_id", rpID)
	return passkey, nil
}

// RecordUse writes back what a sign-in the application verified with a passkey
// changed: the signature counter, the backup state and the uvInitialized flag, and
// the time. Call it before opening the session. The counter must have gone up since
// the passkey's last use (a passkey that always reports 0 has none); otherwise it
// returns ErrPasskeyCloned, records nothing, and the application should refuse the
// sign-in. Returns ErrNotFound when the user has no such passkey, for example
// because it was removed during the ceremony.
func (s *PasskeyService) RecordUse(ctx context.Context, req model.PasskeyUseRequest) error {
	rpID, err := passkeyKey(req.UserID, req.RPID)
	if err != nil {
		return err
	}
	if err := checkCredentialID(req.CredentialID); err != nil {
		return err
	}
	req.RPID = rpID
	err = s.repo.RecordPasskeyUse(ctx, req)
	if errors.Is(err, model.ErrPasskeyCloned) {
		s.logger.Warn(ctx, "Passkey sign-in refused: its signature counter did not go up", "user_id", req.UserID, "rp_id", rpID)
		incMetric(s.metrics, metrics.CounterWebAuthnCloneWarning)
		return err
	}
	return sanitizeError(ctx, s.logger, "record passkey use", err)
}

// List returns a user's passkeys at rpID, oldest first, for an account settings
// page. It reads the replica and creates nothing.
func (s *PasskeyService) List(ctx context.Context, userID, rpID string) ([]*model.Passkey, error) {
	rpID, err := passkeyKey(userID, rpID)
	if err != nil {
		return nil, err
	}
	passkeys, err := s.repo.ListPasskeys(ctx, rpID, userID)
	return passkeys, sanitizeError(ctx, s.logger, "list passkeys", err)
}

// Rename changes the label of one of a user's passkeys. The caller authorizes the
// user; a passkey that belongs to someone else is ErrNotFound.
func (s *PasskeyService) Rename(ctx context.Context, userID, rpID string, credentialID []byte, name string) error {
	rpID, err := passkeyKey(userID, rpID)
	if err != nil {
		return err
	}
	if err := checkCredentialID(credentialID); err != nil {
		return err
	}
	if name, err = passkeyName(name); err != nil {
		return err
	}
	return sanitizeError(ctx, s.logger, "rename passkey", s.repo.RenamePasskey(ctx, rpID, userID, credentialID, name))
}

// Remove deletes one of a user's passkeys, which stops working at once. The caller
// authorizes the user; a passkey that belongs to someone else is ErrNotFound.
// authkit does not stop a user from removing their last way to sign in: that
// depends on which methods the application offers.
func (s *PasskeyService) Remove(ctx context.Context, userID, rpID string, credentialID []byte) error {
	rpID, err := passkeyKey(userID, rpID)
	if err != nil {
		return err
	}
	if err := checkCredentialID(credentialID); err != nil {
		return err
	}
	if err := s.repo.DeletePasskey(ctx, rpID, userID, credentialID); err != nil {
		return sanitizeError(ctx, s.logger, "remove passkey", err)
	}
	s.logger.Info(ctx, "Passkey removed", "user_id", userID, "rp_id", rpID)
	return nil
}
