// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package authkit_test

import (
	"context"

	authkit "github.com/modgudinc/authkit-go"
	"github.com/modgudinc/authkit-go/model"
)

// Freeze the existing named interface: adapters/mocks implementing only the
// previous methods must still satisfy AuthService.
type originalAuthContract interface {
	Login(context.Context, model.LoginRequest) (*model.LoginResponse, error)
	LoginByEmail(context.Context, model.LoginByEmailRequest) (*model.LoginResponse, error)
	MintWorkspaceToken(context.Context, string, string) (*model.WorkspaceTokenResponse, error)
	Logout(context.Context, string) error
	LogoutAll(context.Context, string) error
	RefreshToken(context.Context, model.RefreshRequest) (*model.RefreshResponse, error)
	ValidateJWT(context.Context, string) (*model.JWTClaims, error)
	ChangePassword(context.Context, model.ChangePasswordRequest) error
}
type originalAuthAdapter struct{ originalAuthContract }

var _ authkit.AuthService = originalAuthAdapter{}
