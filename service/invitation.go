// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/model"
	"github.com/modgudinc/authkit-go/repository"
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
		logger: logger,
	}
}

// CreateInvitation creates a new invitation for team member signup
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
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - tenantID: Tenant identifier
//   - createdBy: User UUID of admin/manager creating the invitation
//   - roles: Roles to assign (validated by application layer)
//   - email: Target email address for the invitation (required)
//   - maxUses: Optional maximum uses (defaults to 1 if nil or 0)
//   - expiresIn: Optional expiration duration (defaults to 7 days if nil)
//
// Returns the created invitation or error
func (s *InvitationService) CreateInvitation(ctx context.Context, tenantID, createdBy string, roles []string, email string, maxUses *int, expiresIn *time.Duration) (*model.Invitation, error) {
	if s.logger != nil {
		s.logger.Info("Creating invitation",
			"tenant_id", tenantID,
			"created_by", createdBy,
			"roles", roles,
			"email", email,
		)
	}

	// Generate secure invitation code
	code, err := s.generateInvitationCode()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to generate invitation code",
				"error", err.Error(),
			)
		}
		return nil, fmt.Errorf("failed to generate invitation code: %w", err)
	}

	// Set max uses (default 1)
	uses := DefaultMaxUses
	if maxUses != nil && *maxUses > 0 {
		uses = *maxUses
	}

	// Set expiration (default 7 days)
	expiry := DefaultInvitationExpiry
	if expiresIn != nil && *expiresIn > 0 {
		expiry = *expiresIn
	}
	expiresAt := time.Now().Add(expiry)

	// Create invitation request
	req := model.CreateInvitationRequest{
		Code:      code,
		TenantID:  tenantID,
		CreatedBy: createdBy,
		Roles:     roles,
		Email:     strings.ToLower(strings.TrimSpace(email)),
		ExpiresAt: expiresAt,
		MaxUses:   uses,
	}

	// Create invitation in database
	err = s.repo.CreateInvitation(ctx, req)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to create invitation",
				"tenant_id", tenantID,
				"roles", roles,
				"error", err.Error(),
			)
		}
		return nil, err
	}

	// Retrieve created invitation
	invitation, err := s.repo.GetInvitation(ctx, code)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to retrieve created invitation",
				"code", maskCode(code),
				"error", err.Error(),
			)
		}
		return nil, fmt.Errorf("invitation created but failed to retrieve: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("Invitation created successfully",
			"code", maskCode(code),
			"tenant_id", tenantID,
			"roles", roles,
			"max_uses", uses,
			"expires_at", expiresAt.Format(time.RFC3339),
		)
	}

	return invitation, nil
}

// GetInvitation retrieves an invitation by code
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - code: Invitation code
//
// Returns the invitation or error if not found
func (s *InvitationService) GetInvitation(ctx context.Context, code string) (*model.Invitation, error) {
	if s.logger != nil {
		s.logger.Info("Retrieving invitation",
			"code", maskCode(code),
		)
	}

	invitation, err := s.repo.GetInvitation(ctx, code)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to retrieve invitation",
				"code", maskCode(code),
				"error", err.Error(),
			)
		}
		return nil, err
	}

	if s.logger != nil {
		s.logger.Info("Invitation retrieved successfully",
			"code", maskCode(code),
			"tenant_id", invitation.TenantID,
		)
	}

	return invitation, nil
}

// ValidateInvitation validates an invitation for use
//
// Flow:
// 1. Retrieve invitation by code
// 2. Check expiration
// 3. Check usage limits
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - code: Invitation code
//
// Returns true if valid, false otherwise with error message
func (s *InvitationService) ValidateInvitation(ctx context.Context, code string) (bool, error) {
	if s.logger != nil {
		s.logger.Info("Validating invitation",
			"code", maskCode(code),
		)
	}

	// Get invitation
	invitation, err := s.repo.GetInvitation(ctx, code)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Invitation not found for validation",
				"code", maskCode(code),
				"error", err.Error(),
			)
		}
		return false, err
	}

	// Validate using repository logic
	valid, err := s.repo.IsValid(invitation)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Invitation validation failed",
				"code", maskCode(code),
				"error", err.Error(),
			)
		}
		return false, err
	}

	if s.logger != nil {
		s.logger.Info("Invitation validation completed",
			"code", maskCode(code),
			"valid", valid,
		)
	}

	return valid, nil
}

// AcceptInvitation atomically redeems an invitation and creates the user.
//
// This is the preferred way to onboard an invited user: it validates the
// invitation, consumes one use, and creates the user in a single transaction,
// so a single-use invitation cannot onboard more than one account (no TOCTOU
// over-redemption). The new user's tenant and roles are taken from the
// invitation, and the user is bound to the invitation's target email — only the
// display name and (already-hashed) password come from the caller.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - code: Invitation code being redeemed
//   - email: Email of the user being created; must match the invitation's target
//   - displayName: Display name for the new user
//   - passwordHash: Pre-hashed password (use PasswordService.HashPassword first)
//
// Returns the new user's ID, or an error wrapping model.ErrInvitationInvalid if
// the invitation is unknown, expired, exhausted, or the email does not match.
func (s *InvitationService) AcceptInvitation(ctx context.Context, code, email, displayName, passwordHash string) (uuid.UUID, error) {
	if s.logger != nil {
		s.logger.Info("Accepting invitation",
			"code", maskCode(code),
			"email", email,
		)
	}

	userID, err := s.repo.AcceptInvitation(ctx, code, email, displayName, passwordHash)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("Failed to accept invitation",
				"code", maskCode(code),
				"email", email,
				"error", err.Error(),
			)
		}
		return uuid.Nil, err
	}

	if s.logger != nil {
		s.logger.Info("Invitation accepted successfully",
			"code", maskCode(code),
			"user_id", userID.String(),
		)
	}

	return userID, nil
}

// ListInvitations lists all invitations for a tenant
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - tenantID: Tenant identifier
//
// Returns a list of all invitations ordered by created_at DESC
func (s *InvitationService) ListInvitations(ctx context.Context, tenantID string) ([]*model.Invitation, error) {
	if s.logger != nil {
		s.logger.Info("Listing all invitations",
			"tenant_id", tenantID,
		)
	}

	invitations, err := s.repo.ListInvitations(ctx, tenantID)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to list invitations",
				"tenant_id", tenantID,
				"error", err.Error(),
			)
		}
		return nil, err
	}

	if s.logger != nil {
		s.logger.Info("Invitations listed successfully",
			"tenant_id", tenantID,
			"count", len(invitations),
		)
	}

	return invitations, nil
}

// ListActiveInvitations lists active (not expired, not fully used) invitations for a tenant
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - tenantID: Tenant identifier
//
// Returns a list of active invitations ordered by created_at DESC
func (s *InvitationService) ListActiveInvitations(ctx context.Context, tenantID string) ([]*model.Invitation, error) {
	if s.logger != nil {
		s.logger.Info("Listing active invitations",
			"tenant_id", tenantID,
		)
	}

	invitations, err := s.repo.ListActiveInvitations(ctx, tenantID)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to list active invitations",
				"tenant_id", tenantID,
				"error", err.Error(),
			)
		}
		return nil, err
	}

	if s.logger != nil {
		s.logger.Info("Active invitations listed successfully",
			"tenant_id", tenantID,
			"count", len(invitations),
		)
	}

	return invitations, nil
}

// RevokeInvitation revokes an invitation (soft delete)
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
func (s *InvitationService) RevokeInvitation(ctx context.Context, code string) error {
	if s.logger != nil {
		s.logger.Info("Revoking invitation",
			"code", maskCode(code),
		)
	}

	err := s.repo.InvalidateInvitation(ctx, code)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to revoke invitation",
				"code", maskCode(code),
				"error", err.Error(),
			)
		}
		return err
	}

	if s.logger != nil {
		s.logger.Info("Invitation revoked successfully",
			"code", maskCode(code),
		)
	}

	return nil
}

// DeleteInvitation permanently deletes an invitation
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - code: Invitation code
//
// Returns error if deletion fails
func (s *InvitationService) DeleteInvitation(ctx context.Context, code string) error {
	if s.logger != nil {
		s.logger.Info("Deleting invitation",
			"code", maskCode(code),
		)
	}

	err := s.repo.DeleteInvitation(ctx, code)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to delete invitation",
				"code", maskCode(code),
				"error", err.Error(),
			)
		}
		return err
	}

	if s.logger != nil {
		s.logger.Info("Invitation deleted successfully",
			"code", maskCode(code),
		)
	}

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
	if s.logger != nil {
		s.logger.Info("Incrementing invitation use count",
			"code", maskCode(code),
		)
	}

	err := s.repo.IncrementUseCount(ctx, code)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to increment use count",
				"code", maskCode(code),
				"error", err.Error(),
			)
		}
		return err
	}

	if s.logger != nil {
		s.logger.Info("Invitation use count incremented successfully",
			"code", maskCode(code),
		)
	}

	return nil
}

// CleanupExpiredInvitations removes all expired invitations from the database
//
// # Should be run periodically (e.g., via cron job) to maintain database hygiene
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//
// Returns the number of expired invitations deleted
func (s *InvitationService) CleanupExpiredInvitations(ctx context.Context) (int64, error) {
	if s.logger != nil {
		s.logger.Info("Cleaning up expired invitations")
	}

	count, err := s.repo.CleanupExpiredInvitations(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to cleanup expired invitations",
				"error", err.Error(),
			)
		}
		return 0, err
	}

	if s.logger != nil {
		s.logger.Info("Expired invitations cleaned up successfully",
			"count", count,
		)
	}

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
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))

	hasPending, err := s.repo.HasPending(ctx, normalizedEmail, tenantID)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to check for pending invitation",
				"email", normalizedEmail,
				"tenant_id", tenantID,
				"error", err.Error(),
			)
		}
		return false, err
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
