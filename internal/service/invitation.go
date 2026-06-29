// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/model"
)

const (
	// DefaultInvitationExpiry is the default expiration duration for invitations (7 days)
	DefaultInvitationExpiry = 7 * 24 * time.Hour

	// DefaultMaxUses is the default number of times an invitation can be used
	DefaultMaxUses = 1

	// InvitationCodeLength is the length of generated invitation codes
	InvitationCodeLength = 20

	// InvitationCodeCharset is the character set for invitation codes (uppercase letters and digits)
	InvitationCodeCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// MaxInvitationUses is the maximum number of redemptions a single invitation may
	// permit. A request above this is rejected at creation rather than minting an
	// effectively unlimited signup link (almost always a caller bug).
	MaxInvitationUses = 1000
)

// InvitationService handles invitation-related business logic including
// creation, validation, revocation, and lifecycle management of invitations.
type InvitationService struct {
	repo   *repository.Repository
	logger logger.Logger
}

// NewInvitationService creates a new InvitationService instance
func NewInvitationService(repo *repository.Repository, logger logger.Logger) *InvitationService {
	return &InvitationService{
		repo:   repo,
		logger: ensureLogger(logger),
	}
}

// Create creates a new invitation for team member signup
//
// Flow:
// 1. Generate cryptographically secure invitation code
// 2. Set expiration (default 7 days if not provided)
// 3. Set max uses (default 1 if not provided)
// 4. Create invitation in database
// 5. Return created invitation
//
// Note: Role validation is handled at the application layer, not in this library.
// The library is app-agnostic and accepts any role values.
//
// Note: This does NOT validate email against the tenant's allowed_domains; an
// admin may invite an out-of-domain email on purpose. If you require domain
// enforcement, call TenantService.ValidateDomainAccess before this.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - req: Invitation details (TenantID, CreatedBy, Email, Roles are required;
//     MaxUses defaults to 1, ExpiresIn defaults to 7 days)
//
// Returns the created invitation or error
func (s *InvitationService) Create(ctx context.Context, req model.CreateInvitationRequest) (*model.Invitation, error) {
	// Normalize and validate the target email up front. It is persisted and later
	// bound verbatim onto the created account by Accept (which matches on
	// it), so an empty or malformed value must be rejected here rather than stored.
	// (Roles and allowed_domains remain the application's responsibility — see the
	// notes above; this only checks the email is structurally valid.)
	email := normalizeEmail(req.Email)
	if !isValidEmail(email) {
		return nil, fmt.Errorf("invitation email is required and must be a valid email address")
	}

	// Reject an absurd max-uses up front. A nil/<=0 MaxUses falls back to the default
	// (1) below; an over-large value would mint an effectively unlimited signup link.
	if req.MaxUses != nil && *req.MaxUses > MaxInvitationUses {
		return nil, fmt.Errorf("invitation max_uses must not exceed %d (got %d)", MaxInvitationUses, *req.MaxUses)
	}

	s.logger.Info(ctx, "Creating invitation",
		"tenant_id", req.TenantID,
		"created_by", req.CreatedBy,
		"roles", req.Roles,
		"email", maskEmail(email),
	)

	// Generate secure invitation code
	code, err := s.generateInvitationCode()
	if err != nil {
		s.logger.Error(ctx, "Failed to generate invitation code",
			"error", err.Error(),
		)
		return nil, sanitizeError(ctx, s.logger, "generate invitation code", err)
	}

	// Set max uses (default 1)
	uses := DefaultMaxUses
	if req.MaxUses != nil && *req.MaxUses > 0 {
		uses = *req.MaxUses
	}

	// Set expiration (default 7 days)
	expiry := DefaultInvitationExpiry
	if req.ExpiresIn != nil && *req.ExpiresIn > 0 {
		expiry = *req.ExpiresIn
	}
	expiresAt := time.Now().Add(expiry)

	// Create invitation in database
	err = s.repo.CreateInvitation(ctx, repository.InsertInvitationParams{
		Code:      code,
		TenantID:  req.TenantID,
		CreatedBy: req.CreatedBy,
		Roles:     req.Roles,
		Email:     email,
		ExpiresAt: expiresAt,
		MaxUses:   uses,
	})
	if err != nil {
		s.logger.Error(ctx, "Failed to create invitation",
			"tenant_id", req.TenantID,
			"roles", req.Roles,
			"error", err.Error(),
		)
		return nil, sanitizeError(ctx, s.logger, "create invitation", err)
	}

	// Retrieve created invitation
	invitation, err := s.repo.GetInvitation(ctx, code)
	if err != nil {
		s.logger.Error(ctx, "Failed to retrieve created invitation",
			"code", maskCode(code),
			"error", err.Error(),
		)
		return nil, sanitizeError(ctx, s.logger, "retrieve created invitation", err)
	}

	s.logger.Info(ctx, "Invitation created successfully",
		"code", maskCode(code),
		"tenant_id", req.TenantID,
		"roles", req.Roles,
		"max_uses", uses,
		"expires_at", expiresAt.Format(time.RFC3339),
	)

	return invitation, nil
}

// Get retrieves an invitation by code
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - code: Invitation code
//
// Returns the invitation or error if not found
func (s *InvitationService) Get(ctx context.Context, code string) (*model.Invitation, error) {
	s.logger.Info(ctx, "Retrieving invitation",
		"code", maskCode(code),
	)

	invitation, err := s.repo.GetInvitation(ctx, code)
	if err != nil {
		s.logger.Error(ctx, "Failed to retrieve invitation",
			"code", maskCode(code),
			"error", err.Error(),
		)
		return nil, sanitizeError(ctx, s.logger, "get invitation", err)
	}

	s.logger.Info(ctx, "Invitation retrieved successfully",
		"code", maskCode(code),
		"tenant_id", invitation.TenantID,
	)

	return invitation, nil
}

// Validate reports whether an invitation is currently usable.
//
// Flow:
// 1. Retrieve invitation by code
// 2. Check expiration
// 3. Check usage limits
//
// The boolean is the answer; the error is reserved for genuine system faults.
// A code that is unknown, expired, or exhausted is a normal "not usable" outcome
// and is returned as (false, nil) — callers should branch on the bool, not on
// err. Only a real storage/driver failure yields a non-nil (sanitized) error.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - code: Invitation code
//
// Returns (true, nil) if usable, (false, nil) if not usable, (false, err) on fault.
func (s *InvitationService) Validate(ctx context.Context, code string) (bool, error) {
	s.logger.Info(ctx, "Validating invitation",
		"code", maskCode(code),
	)

	// Get invitation. An unknown code is simply not usable, not a fault.
	invitation, err := s.repo.GetInvitation(ctx, code)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return false, nil
		}
		s.logger.Error(ctx, "Failed to load invitation for validation",
			"code", maskCode(code),
			"error", err.Error(),
		)
		return false, sanitizeError(ctx, s.logger, "validate invitation", err)
	}

	// Validate using repository logic. Expired/exhausted is a known not-usable
	// outcome surfaced via the bool, not the error.
	valid, err := s.repo.IsValid(invitation)
	if err != nil {
		if errors.Is(err, model.ErrInvitationInvalid) {
			return false, nil
		}
		s.logger.Error(ctx, "Invitation validation failed",
			"code", maskCode(code),
			"error", err.Error(),
		)
		return false, sanitizeError(ctx, s.logger, "validate invitation", err)
	}

	s.logger.Info(ctx, "Invitation validation completed",
		"code", maskCode(code),
		"valid", valid,
	)

	return valid, nil
}

// Accept atomically redeems an invitation and creates the user.
//
// This is the preferred way to onboard an invited user: it validates the
// invitation, consumes one use, and creates the user in a single transaction,
// so a single-use invitation cannot onboard more than one account (no TOCTOU
// over-redemption). The new user's tenant and roles are taken from the
// invitation, and the user is bound to the invitation's target email — only the
// display name and (already-hashed) password come from the caller.
//
// Note: it validates expiry, remaining uses, and the email-matches-invitation,
// but does NOT check the tenant's allowed_domains (enforce that at invitation
// creation time if you need it).
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - req: AcceptInvitationRequest with the code, target email, display name, and
//     pre-hashed password
//
// Returns the new user's ID, or an error wrapping model.ErrInvitationInvalid if
// the invitation is unknown, expired, exhausted, or the email does not match.
func (s *InvitationService) Accept(ctx context.Context, req model.AcceptInvitationRequest) (string, error) {
	s.logger.Info(ctx, "Accepting invitation",
		"code", maskCode(req.Code),
		"email", maskEmail(req.Email),
	)

	userID, err := s.repo.AcceptInvitation(ctx, req.Code, req.Email, req.DisplayName, req.PasswordHash)
	if err != nil {
		s.logger.Warn(ctx, "Failed to accept invitation",
			"code", maskCode(req.Code),
			"email", maskEmail(req.Email),
			"error", err.Error(),
		)
		return "", sanitizeError(ctx, s.logger, "accept invitation", err)
	}

	s.logger.Info(ctx, "Invitation accepted successfully",
		"code", maskCode(req.Code),
		"user_id", userID,
	)

	return userID, nil
}

// List lists all invitations for a tenant
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - tenantID: Tenant identifier
//
// Returns a list of all invitations ordered by created_at DESC
func (s *InvitationService) List(ctx context.Context, tenantID string) ([]*model.Invitation, error) {
	s.logger.Info(ctx, "Listing all invitations",
		"tenant_id", tenantID,
	)

	invitations, err := s.repo.ListInvitations(ctx, tenantID)
	if err != nil {
		s.logger.Error(ctx, "Failed to list invitations",
			"tenant_id", tenantID,
			"error", err.Error(),
		)
		return nil, sanitizeError(ctx, s.logger, "list invitations", err)
	}

	s.logger.Info(ctx, "Invitations listed successfully",
		"tenant_id", tenantID,
		"count", len(invitations),
	)

	return invitations, nil
}

// ListActive lists active (not expired, not fully used) invitations for a tenant
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - tenantID: Tenant identifier
//
// Returns a list of active invitations ordered by created_at DESC
func (s *InvitationService) ListActive(ctx context.Context, tenantID string) ([]*model.Invitation, error) {
	s.logger.Info(ctx, "Listing active invitations",
		"tenant_id", tenantID,
	)

	invitations, err := s.repo.ListActiveInvitations(ctx, tenantID)
	if err != nil {
		s.logger.Error(ctx, "Failed to list active invitations",
			"tenant_id", tenantID,
			"error", err.Error(),
		)
		return nil, sanitizeError(ctx, s.logger, "list active invitations", err)
	}

	s.logger.Info(ctx, "Active invitations listed successfully",
		"tenant_id", tenantID,
		"count", len(invitations),
	)

	return invitations, nil
}

// Revoke revokes an invitation (soft delete)
//
// Flow:
// 1. Invalidate invitation by setting current_uses = max_uses
// 2. Preserves audit trail
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - code: Invitation code
//
// Returns error if revocation fails
func (s *InvitationService) Revoke(ctx context.Context, code string) error {
	s.logger.Info(ctx, "Revoking invitation",
		"code", maskCode(code),
	)

	err := s.repo.InvalidateInvitation(ctx, code)
	if err != nil {
		s.logger.Error(ctx, "Failed to revoke invitation",
			"code", maskCode(code),
			"error", err.Error(),
		)
		return sanitizeError(ctx, s.logger, "revoke invitation", err)
	}

	s.logger.Info(ctx, "Invitation revoked successfully",
		"code", maskCode(code),
	)

	return nil
}

// Delete permanently deletes an invitation
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - code: Invitation code
//
// Returns error if deletion fails
func (s *InvitationService) Delete(ctx context.Context, code string) error {
	s.logger.Info(ctx, "Deleting invitation",
		"code", maskCode(code),
	)

	err := s.repo.DeleteInvitation(ctx, code)
	if err != nil {
		s.logger.Error(ctx, "Failed to delete invitation",
			"code", maskCode(code),
			"error", err.Error(),
		)
		return sanitizeError(ctx, s.logger, "delete invitation", err)
	}

	s.logger.Info(ctx, "Invitation deleted successfully",
		"code", maskCode(code),
	)

	return nil
}

// IncrementUseCount increments the use count for an invitation
//
// Flow:
// 1. Atomically increment current_uses
// 2. Database ensures current_uses < max_uses constraint
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - code: Invitation code
//
// Returns error if increment fails or max uses exceeded
func (s *InvitationService) IncrementUseCount(ctx context.Context, code string) error {
	s.logger.Info(ctx, "Incrementing invitation use count",
		"code", maskCode(code),
	)

	err := s.repo.IncrementUseCount(ctx, code)
	if err != nil {
		s.logger.Error(ctx, "Failed to increment use count",
			"code", maskCode(code),
			"error", err.Error(),
		)
		return sanitizeError(ctx, s.logger, "increment use count", err)
	}

	s.logger.Info(ctx, "Invitation use count incremented successfully",
		"code", maskCode(code),
	)

	return nil
}

// CleanupExpired removes all expired invitations from the database
//
// # Should be run periodically (e.g., via cron job) to maintain database hygiene
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//
// Returns the number of expired invitations deleted
func (s *InvitationService) CleanupExpired(ctx context.Context) (int64, error) {
	s.logger.Info(ctx, "Cleaning up expired invitations")

	count, err := s.repo.CleanupExpiredInvitations(ctx)
	if err != nil {
		s.logger.Error(ctx, "Failed to cleanup expired invitations",
			"error", err.Error(),
		)
		return 0, sanitizeError(ctx, s.logger, "cleanup expired invitations", err)
	}

	s.logger.Info(ctx, "Expired invitations cleaned up successfully",
		"count", count,
	)

	return count, nil
}

// HasPending checks if there's an active invitation for an email in a tenant
//
// # Useful when checking invitation status for external actors
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - email: Email address to check
//   - tenantID: Tenant identifier
//
// Returns true if an active (not expired, not fully used) invitation exists
func (s *InvitationService) HasPending(ctx context.Context, email, tenantID string) (bool, error) {
	normalizedEmail := normalizeEmail(email)

	hasPending, err := s.repo.HasPending(ctx, normalizedEmail, tenantID)
	if err != nil {
		s.logger.Error(ctx, "Failed to check for pending invitation",
			"email", maskEmail(normalizedEmail),
			"tenant_id", tenantID,
			"error", err.Error(),
		)
		return false, sanitizeError(ctx, s.logger, "check pending invitation", err)
	}

	return hasPending, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// generateInvitationCode generates a cryptographically secure invitation code
// Format: 20-character uppercase alphanumeric string (A-Z, 0-9)
func (s *InvitationService) generateInvitationCode() (string, error) {
	code := make([]byte, InvitationCodeLength)
	charsetLen := len(InvitationCodeCharset)
	for i := range code {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(charsetLen)))
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %w", err)
		}
		code[i] = InvitationCodeCharset[num.Int64()]
	}

	return string(code), nil
}

// maskCode masks an invitation code for logging (shows first 4 chars + ***)
// Example: "ABC123XYZ..." -> "ABC1***"
func maskCode(code string) string {
	if len(code) <= 4 {
		return "***"
	}
	return code[:4] + "***"
}
