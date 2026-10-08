// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
)

// ExternalIdentityService links accounts at outside sign-in providers (Google,
// GitHub, an enterprise OIDC issuer) to authkit users. It does not speak OAuth or
// OIDC: the application verifies the provider's response with its own client
// (golang.org/x/oauth2, github.com/coreos/go-oidc) and passes the result here.
// Requires migration 000004.
type ExternalIdentityService struct {
	repo    *repository.Repository
	logger  logger.Logger
	metrics metrics.Metrics
}

// NewExternalIdentityService creates a new ExternalIdentityService.
func NewExternalIdentityService(repo *repository.Repository, logger logger.Logger, m metrics.Metrics) *ExternalIdentityService {
	return &ExternalIdentityService{repo: repo, logger: ensureLogger(logger), metrics: m}
}

// identityKey validates and normalizes a (provider, subject) pair. The provider
// name is lowercased; the subject is the provider's case-sensitive id and must be
// 1 to 255 characters with no surrounding whitespace.
func identityKey(provider, subject string) (string, error) {
	provider, err := normalizeName(provider)
	if err != nil {
		return "", err
	}
	if !validSessionReference(subject) {
		return "", fmt.Errorf("subject must be 1 to 255 characters without surrounding whitespace: %w", model.ErrInvalidInput)
	}
	return provider, nil
}

// providerEmail normalizes the email a provider reported; empty is allowed.
func providerEmail(email string) (string, error) {
	email = normalizeEmail(email)
	if email != "" && !isValidEmail(email) {
		return "", fmt.Errorf("provider email is malformed: %w", model.ErrInvalidInput)
	}
	return email, nil
}

// Resolve returns the user a verified provider sign-in belongs to, linking or
// creating one under these rules:
//
//   - A returning sign-in is found by (Provider, Subject) alone, whatever email the
//     provider now reports. The user's own email is never changed.
//   - A first sign-in may be linked to the user that owns its email only when the
//     provider verified that email (EmailVerified), the user has no password, and
//     the user is not linked to another account at the same provider. Otherwise
//     Resolve returns ErrIdentityLinkRequired and changes nothing: have the person
//     sign in to that user, then call Link. An unverified email never finds a user.
//   - With no user for the email, CreateUser creates one without a password (it
//     needs a verified email, else ErrEmailNotVerified); without it, ErrNotFound.
//
// Resolve does not open a session or check account status: pass the user to
// VerifiedLoginService.OpenSession, which refuses disabled and locked accounts.
func (s *ExternalIdentityService) Resolve(ctx context.Context, req model.ResolveExternalIdentityRequest) (*model.ResolvedExternalIdentity, error) {
	provider, err := identityKey(req.Provider, req.Subject)
	if err != nil {
		return nil, err
	}
	email, err := providerEmail(req.Email)
	if err != nil {
		return nil, err
	}
	res, err := s.repo.ResolveExternalIdentity(ctx, repository.ResolveExternalIdentityParams{
		Provider: provider, Subject: req.Subject, Email: email, EmailVerified: req.EmailVerified,
		DisplayName: strings.TrimSpace(req.DisplayName), CreateUser: req.CreateUser,
	})
	var refused *repository.LinkRefusedError
	if errors.As(err, &refused) {
		s.logger.Warn(ctx, "Sign-in identity not linked automatically", "provider", provider, "reason", refused.Reason, "email", maskEmail(email))
		incMetric(s.metrics, metrics.CounterIdentityLinkRefused, "reason", refused.Reason)
		return nil, model.ErrIdentityLinkRequired
	}
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "resolve external identity", err)
	}
	s.logger.Info(ctx, "External identity resolved", "provider", provider, "user_id", res.User.ID,
		"created", res.Created, "linked", res.Linked)
	return &model.ResolvedExternalIdentity{User: res.User, Identity: res.Identity, Created: res.Created, Linked: res.Linked}, nil
}

// Link links a provider identity to a user the application has authenticated, for
// an account settings page or to finish a sign-in that returned
// ErrIdentityLinkRequired. No email rules apply: the caller vouches for UserID.
// Linking an identity the user already has is a no-op that refreshes its email.
// Returns ErrNotFound for an unknown user and ErrIdentityAlreadyLinked when
// another user has the identity.
func (s *ExternalIdentityService) Link(ctx context.Context, req model.LinkExternalIdentityRequest) (*model.ExternalIdentity, error) {
	provider, err := identityKey(req.Provider, req.Subject)
	if err != nil {
		return nil, err
	}
	if req.UserID == "" {
		return nil, fmt.Errorf("user id is required: %w", model.ErrInvalidInput)
	}
	email, err := providerEmail(req.Email)
	if err != nil {
		return nil, err
	}
	identity, err := s.repo.LinkExternalIdentity(ctx, req.UserID, provider, req.Subject, email, req.EmailVerified)
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "link external identity", err)
	}
	s.logger.Info(ctx, "External identity linked", "provider", provider, "user_id", req.UserID)
	return identity, nil
}

// Unlink removes one of a user's linked identities. The caller authorizes the
// user; a link that belongs to someone else is ErrNotFound. authkit does not stop a
// user from removing their last way to sign in: that depends on which methods the
// application offers.
func (s *ExternalIdentityService) Unlink(ctx context.Context, userID, provider, subject string) error {
	provider, err := identityKey(provider, subject)
	if err != nil {
		return err
	}
	if userID == "" {
		return fmt.Errorf("user id is required: %w", model.ErrInvalidInput)
	}
	if err := s.repo.UnlinkExternalIdentity(ctx, userID, provider, subject); err != nil {
		return sanitizeError(ctx, s.logger, "unlink external identity", err)
	}
	s.logger.Info(ctx, "External identity unlinked", "provider", provider, "user_id", userID)
	return nil
}

// Get returns the link for a provider identity (for example, to map a provider's
// webhook to a user). It is a management read, not a sign-in: use Resolve for that.
func (s *ExternalIdentityService) Get(ctx context.Context, provider, subject string) (*model.ExternalIdentity, error) {
	provider, err := identityKey(provider, subject)
	if err != nil {
		return nil, err
	}
	identity, err := s.repo.GetExternalIdentity(ctx, provider, subject)
	return identity, sanitizeError(ctx, s.logger, "get external identity", err)
}

// ListByUser returns a user's linked identities, by provider.
func (s *ExternalIdentityService) ListByUser(ctx context.Context, userID string) ([]*model.ExternalIdentity, error) {
	if userID == "" {
		return nil, fmt.Errorf("user id is required: %w", model.ErrInvalidInput)
	}
	identities, err := s.repo.ListExternalIdentities(ctx, userID)
	return identities, sanitizeError(ctx, s.logger, "list external identities", err)
}
