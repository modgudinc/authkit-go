// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package authkit

import "github.com/modgudinc/authkit-go/model"

var (
	ErrSessionDisabled = model.ErrSessionDisabled
	ErrSessionRequired = model.ErrSessionRequired
	ErrSessionRevoked  = model.ErrSessionRevoked
)

var (
	ErrIdentityLinkRequired  = model.ErrIdentityLinkRequired
	ErrIdentityAlreadyLinked = model.ErrIdentityAlreadyLinked
	ErrEmailNotVerified      = model.ErrEmailNotVerified
)

var (
	ErrPasskeyAlreadyRegistered = model.ErrPasskeyAlreadyRegistered
	ErrPasskeyCloned            = model.ErrPasskeyCloned
)

var (
	ErrSecondFactorRequired    = model.ErrSecondFactorRequired
	ErrInvalidSecondFactor     = model.ErrInvalidSecondFactor
	ErrTwoFactorAlreadyEnabled = model.ErrTwoFactorAlreadyEnabled
	ErrTwoFactorNotConfigured  = model.ErrTwoFactorNotConfigured
)

// Sentinel errors re-exported from the model package for convenience, so callers
// can write errors.Is(err, authkit.ErrInvalidCredentials). These are the same
// values the services return (model.Err*), so matching against either works.
var (
	ErrNotFound                   = model.ErrNotFound
	ErrInvalidCredentials         = model.ErrInvalidCredentials
	ErrAccountDisabled            = model.ErrAccountDisabled
	ErrAccountLocked              = model.ErrAccountLocked
	ErrInvalidToken               = model.ErrInvalidToken
	ErrTokenRevoked               = model.ErrTokenRevoked
	ErrNoActiveMembership         = model.ErrNoActiveMembership
	ErrLastRoleHolder             = model.ErrLastRoleHolder
	ErrInvalidRefreshToken        = model.ErrInvalidRefreshToken
	ErrRefreshTokenReuse          = model.ErrRefreshTokenReuse
	ErrInvalidOTP                 = model.ErrInvalidOTP
	ErrOTPLockedOut               = model.ErrOTPLockedOut
	ErrOTPRateLimited             = model.ErrOTPRateLimited
	ErrOTPSecretMissing           = model.ErrOTPSecretMissing
	ErrInvalidAPIKey              = model.ErrInvalidAPIKey
	ErrIncorrectPassword          = model.ErrIncorrectPassword
	ErrInvitationInvalid          = model.ErrInvitationInvalid
	ErrUserExists                 = model.ErrUserExists
	ErrPasswordTooWeak            = model.ErrPasswordTooWeak
	ErrSecretEncryptionKeyMissing = model.ErrSecretEncryptionKeyMissing
	ErrRateLimited                = model.ErrRateLimited
	ErrInvalidInput               = model.ErrInvalidInput
	ErrValueTooLong               = model.ErrValueTooLong
	ErrInternal                   = model.ErrInternal
)
