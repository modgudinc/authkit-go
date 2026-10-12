// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"github.com/modgudinc/authkit-go/internal/repository"
)

// signingIn detaches ctx from a caller's transaction (authkit.WithTx). Signing in
// and checking a credential record what happened (a failed attempt, a lockout, a
// revoked token family, a code or a signature counter used up), and those records
// must commit whatever the caller then does with its transaction.
func signingIn(ctx context.Context) context.Context {
	return repository.Detach(ctx)
}
