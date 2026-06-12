// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"errors"
	"fmt"

	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/model"
)

// publicSentinels are the errors callers are expected to branch on with
// errors.Is. sanitizeError lets these pass through unchanged.
var publicSentinels = []error{
	model.ErrNotFound,
	model.ErrInvalidCredentials,
	model.ErrAccountDisabled,
	model.ErrAccountLocked,
	model.ErrInvalidToken,
	model.ErrTokenRevoked,
	model.ErrInvalidRefreshToken,
	model.ErrRefreshTokenReuse,
	model.ErrInvalidOTP,
	model.ErrOTPLockedOut,
	model.ErrOTPRateLimited,
	model.ErrInvalidAPIKey,
	model.ErrIncorrectPassword,
	model.ErrInvitationInvalid,
	model.ErrUserExists,
}

// sanitizeError generalizes a repository error before it crosses the public API
// boundary. A known sentinel passes through so callers can still errors.Is it;
// any other error (a genuine DB/driver fault) is logged in full server-side and
// replaced with model.ErrInternal so driver/schema/constraint details are not
// exposed to callers that may render err.Error() to end users.
func sanitizeError(log logger.Logger, op string, err error) error {
	if err == nil {
		return nil
	}
	for _, sentinel := range publicSentinels {
		if errors.Is(err, sentinel) {
			return err
		}
	}
	if log != nil {
		log.Error("internal error", "op", op, "error", err.Error())
	}
	return fmt.Errorf("%s: %w", op, model.ErrInternal)
}
