// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
)

// maxNameLength bounds sign-in method and provider names (VARCHAR(64) columns).
const maxNameLength = 64

// normalizeName lowercases and trims a sign-in method or provider name and checks
// it is 1 to 64 of [a-z0-9._:-], starting with a letter or digit. These names key
// audit records and identity links, so "Google" and "google " must be one name.
func normalizeName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || len(name) > maxNameLength {
		return "", fmt.Errorf("name must be 1 to %d characters: %w", maxNameLength, model.ErrInvalidInput)
	}
	for i, ch := range name {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9':
		case i > 0 && (ch == '.' || ch == '_' || ch == ':' || ch == '-'):
		default:
			return "", fmt.Errorf("name may contain only letters, digits, '.', '_', ':' and '-': %w", model.ErrInvalidInput)
		}
	}
	return name, nil
}

// OpenSession opens a session for a user the application has already verified by
// some means other than an authkit password: an OAuth or OIDC provider, a signed
// email link, an OTP, a passkey, an approved device code. It checks no credential.
//
// The caller vouches for req.UserID, so it must come from the application's own
// verification and never from request input. It applies the same account gates as
// a login (ErrAccountDisabled, ErrAccountLocked; ErrNotFound for an unknown user)
// and the same workspace selection as LoginByEmail (req.TenantID, else the only
// active membership; ErrNoActiveMembership for a workspace the user cannot use).
//
// With session support enabled (SessionOptional or SessionRequired) it creates a
// session record that stores req.SignInMethod, bound to req.Installation when one
// is given, and returns it in the response; a session without an installation is
// valid in SessionRequired mode too. In SessionDisabled mode it opens a plain
// identity session (Session is nil) and req.Installation is refused with
// ErrSessionDisabled. It does not consult Config.RateLimiter: throttle the
// application's own verification step instead.
func (s *AuthService) OpenSession(ctx context.Context, req model.OpenSessionRequest) (*model.OpenSessionResponse, error) {
	method, err := normalizeName(req.SignInMethod)
	if err != nil {
		return nil, err
	}
	if method == model.SignInMethodPassword {
		return nil, fmt.Errorf("sign-in method %q is reserved for authkit password logins: %w", method, model.ErrInvalidInput)
	}
	if req.UserID == "" {
		return nil, fmt.Errorf("user id is required: %w", model.ErrInvalidInput)
	}
	if err := s.tokenService.checkOptionalInstallation(req.Installation); err != nil {
		return nil, err
	}

	// Read from the PRIMARY: the account gate must observe a just-committed disable
	// or lock, as on the password login path.
	user, err := s.repo.GetByIDFromPrimary(ctx, req.UserID)
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "load user", err)
	}
	if err := accountGate(user); err != nil {
		s.logger.Warn(ctx, "Verified login refused: account not active", "user_id", user.ID, "error", err.Error())
		return nil, err
	}

	memberships, selected, err := s.selectWorkspace(ctx, user.ID, req.TenantID)
	if err != nil {
		return nil, err
	}

	refreshToken, session, err := s.tokenService.openVerifiedSession(ctx, user, req.SessionInfo, req.Installation, method)
	if errors.Is(err, model.ErrInvalidCredentials) {
		// The account changed between the gate above and the session insert (the
		// repository re-checks it under a row lock). Report what changed.
		err = s.recheckAccount(ctx, user.ID)
	}
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "open verified session", err)
	}

	resp := &model.OpenSessionResponse{
		LoginResponse: model.LoginResponse{
			RefreshToken: refreshToken,
			User:         user,
			Memberships:  membershipValues(memberships),
		},
		Session: session,
	}
	if selected != nil {
		accessToken, expiresIn, err := s.tokenService.mintSessionAccess(user, selected, session)
		if err != nil {
			return nil, sanitizeError(ctx, s.logger, "mint access token", err)
		}
		resp.AccessToken = accessToken
		resp.ExpiresIn = expiresIn
		resp.TenantID = selected.TenantID
	}

	if err := s.repo.UpdateLastLogin(ctx, user.ID); err != nil {
		s.logger.Warn(ctx, "Failed to update last login timestamp", "error", err.Error())
		incMetric(s.metrics, metrics.CounterBestEffortWriteFailure, "op", "update_last_login")
	}
	s.logger.Info(ctx, "Verified login successful", "user_id", user.ID, "sign_in_method", method,
		"session_bound", session != nil, "workspace_selected", selected != nil)
	incMetric(s.metrics, metrics.CounterVerifiedLogin, "method", method)
	return resp, nil
}

// accountGate refuses a disabled account, or a locked one whose lock has not
// expired, with the specific sentinel: the caller has already identified the user,
// so there is nothing to hide.
func accountGate(user *model.User) error {
	if !user.IsEnabled {
		return model.ErrAccountDisabled
	}
	if isUserLocked(user) {
		return model.ErrAccountLocked
	}
	return nil
}

// recheckAccount explains a session insert refused because the account changed
// after it was loaded: disabled or locked, or its credentials changed (a logout-all
// or password change), which revokes the sign-in in progress.
func (s *AuthService) recheckAccount(ctx context.Context, userID string) error {
	user, err := s.repo.GetByIDFromPrimary(ctx, userID)
	if err != nil {
		return err
	}
	if err := accountGate(user); err != nil {
		return err
	}
	return model.ErrSessionRevoked
}
