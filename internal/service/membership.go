// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/model"
)

// MembershipService manages the user<->tenant membership graph: which global
// identity belongs to which tenant, with which roles. authkit owns the graph; the
// embedding application interprets the (opaque) role strings.
//
// Roles and revocation are reflected in access tokens via the per-membership
// token_version: UpdateRoles and Remove bump it, so an already-issued workspace
// access token (which embeds the roles) is rejected by AuthService.ValidateJWT and
// the next RefreshToken/MintWorkspaceToken re-reads the new state. The identity
// session (refresh token) is NOT revoked by membership changes — the user keeps
// access to their other workspaces.
type MembershipService struct {
	repo   *repository.Repository
	logger logger.Logger
}

// NewMembershipService creates a new MembershipService instance.
func NewMembershipService(repo *repository.Repository, logger logger.Logger) *MembershipService {
	return &MembershipService{
		repo:   repo,
		logger: ensureLogger(logger),
	}
}

// Add grants (or updates) a user's membership in a tenant with the given roles. It
// is an idempotent upsert keyed by (UserID, TenantID): re-adding an existing
// membership replaces its roles and reactivates it. A user_id/tenant_id with no
// parent row returns model.ErrNotFound.
func (s *MembershipService) Add(ctx context.Context, req model.AddMembershipRequest) error {
	return sanitizeError(ctx, s.logger, "add membership", s.repo.AddMembership(ctx, req))
}

// Remove revokes a user's membership in a tenant (soft-revoke: the row is retained
// with status=suspended and the membership token_version is bumped, invalidating
// that workspace's access tokens). Returns model.ErrNotFound when no such membership
// exists. Re-grant later with Add.
func (s *MembershipService) Remove(ctx context.Context, userID, tenantID string) error {
	return sanitizeError(ctx, s.logger, "remove membership", s.repo.RemoveMembership(ctx, userID, tenantID))
}

// UpdateRoles replaces a membership's roles in a tenant and bumps the membership
// token_version so the workspace's already-issued access tokens are invalidated (the
// next refresh re-reads the new roles). Returns model.ErrNotFound when no such
// membership exists.
func (s *MembershipService) UpdateRoles(ctx context.Context, userID, tenantID string, roles []string) error {
	return sanitizeError(ctx, s.logger, "update membership roles", s.repo.UpdateMembershipRoles(ctx, userID, tenantID, roles))
}

// Get returns a single (user, tenant) membership, or model.ErrNotFound if none
// exists.
func (s *MembershipService) Get(ctx context.Context, userID, tenantID string) (*model.Membership, error) {
	m, err := s.repo.GetMembership(ctx, userID, tenantID)
	return m, sanitizeError(ctx, s.logger, "get membership", err)
}

// ListByUser returns a user's memberships (their workspaces), newest first. The
// result includes suspended memberships; filter on Status for active-only.
func (s *MembershipService) ListByUser(ctx context.Context, userID string) ([]*model.Membership, error) {
	ms, err := s.repo.ListMembershipsByUser(ctx, userID)
	return ms, sanitizeError(ctx, s.logger, "list memberships by user", err)
}

// ListByTenant returns a tenant's memberships (its members), newest first. The
// result includes suspended memberships; filter on Status for active-only.
func (s *MembershipService) ListByTenant(ctx context.Context, tenantID string) ([]*model.Membership, error) {
	ms, err := s.repo.ListMembershipsByTenant(ctx, tenantID)
	return ms, sanitizeError(ctx, s.logger, "list memberships by tenant", err)
}

// CountByTenant returns the number of memberships in a tenant (active and suspended
// both count).
func (s *MembershipService) CountByTenant(ctx context.Context, tenantID string) (int, error) {
	n, err := s.repo.CountMembershipsByTenant(ctx, tenantID)
	return n, sanitizeError(ctx, s.logger, "count memberships", err)
}
