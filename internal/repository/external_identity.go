// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/modgudinc/authkit-go/model"
)

// External identity repository methods (migration 000004). A row links one account
// at an outside sign-in provider, keyed by (provider, subject), to one user.
//
// - ResolveExternalIdentity - Find, link or create the user for a verified provider sign-in
// - LinkExternalIdentity    - Link an identity to a user the application authenticated
// - UnlinkExternalIdentity  - Remove one of a user's links
// - GetExternalIdentity     - One link by (provider, subject) (replica)
// - ListExternalIdentities  - A user's links (replica)
//
// Writes lock the user row before the identity row, matching the user-first order
// of the session mutations.

const externalIdentityColumns = "provider, subject, user_id, email, email_verified, created_at, last_sign_in_at"

// Reasons ResolveExternalIdentity refuses to link a sign-in to the user that owns
// its verified email.
const (
	// LinkRefusedHasPassword: the user has a password. Whoever created the account
	// may not own the email (pre-account hijacking), so the owner links it instead.
	LinkRefusedHasPassword = "has_password"
	// LinkRefusedProviderAccountMismatch: the user is already linked to a different
	// account at the same provider. Providers can reassign an email to a new account
	// (a recycled workplace address), so the subject decides, not the email.
	LinkRefusedProviderAccountMismatch = "provider_account_mismatch"
)

// LinkRefusedError reports why ResolveExternalIdentity would not link a sign-in to
// the user found by its verified email. It unwraps to model.ErrIdentityLinkRequired.
type LinkRefusedError struct {
	Reason string
}

func (e *LinkRefusedError) Error() string {
	return model.ErrIdentityLinkRequired.Error() + " (" + e.Reason + ")"
}

// Unwrap lets errors.Is(err, model.ErrIdentityLinkRequired) match.
func (e *LinkRefusedError) Unwrap() error { return model.ErrIdentityLinkRequired }

// ResolveExternalIdentityParams is a provider sign-in the service has validated and
// normalized: Provider lowercased, Email normalized (possibly empty).
type ResolveExternalIdentityParams struct {
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
	DisplayName   string
	CreateUser    bool
}

// ResolveExternalIdentityResult is the user a sign-in belongs to and its link.
type ResolveExternalIdentityResult struct {
	User     *model.User
	Identity *model.ExternalIdentity
	Created  bool
	Linked   bool
}

func scanExternalIdentity(row scannable) (*model.ExternalIdentity, error) {
	var e model.ExternalIdentity
	if err := row.Scan(&e.Provider, &e.Subject, &e.UserID, &e.Email, &e.EmailVerified, &e.CreatedAt, &e.LastSignInAt); err != nil {
		return nil, err
	}
	return &e, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == uniqueViolation
}

// ResolveExternalIdentity finds the user a verified provider sign-in belongs to, in
// one transaction on the primary:
//
//  1. (provider, subject) is already linked: that user. The link's email snapshot
//     and last_sign_in_at are updated; the user's own email never changes.
//  2. Otherwise only a verified email may find a user (case-insensitively). It is
//     linked when the user has no password and no other account at this provider;
//     otherwise a *LinkRefusedError (model.ErrIdentityLinkRequired) changes nothing.
//  3. No user has the email: with CreateUser, a user without a password is created
//     and linked; without it, model.ErrNotFound.
//
// Without a verified email, steps 2 and 3 return model.ErrNotFound, or
// model.ErrEmailNotVerified when CreateUser was asked for, so an unverified address
// neither finds nor reveals an account.
func (r *Repository) ResolveExternalIdentity(ctx context.Context, p ResolveExternalIdentityParams) (*ResolveExternalIdentityResult, error) {
	res, err := r.resolveExternalIdentityOnce(ctx, p)
	if isUniqueViolation(err) {
		// A concurrent sign-in linked this identity, or created a user for this email,
		// after our reads. Its transaction has committed, so the retry sees the result.
		res, err = r.resolveExternalIdentityOnce(ctx, p)
	}
	return res, err
}

func (r *Repository) resolveExternalIdentityOnce(ctx context.Context, p ResolveExternalIdentityParams) (*ResolveExternalIdentityResult, error) {
	tx, err := r.rw.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now()

	identity, err := scanExternalIdentity(tx.QueryRowContext(ctx, r.q("SELECT "+externalIdentityColumns+
		" FROM {{schema}}.external_identities WHERE provider=$1 AND subject=$2 FOR UPDATE"), p.Provider, p.Subject))
	switch {
	case err == nil:
		user, err := scanUser(tx.QueryRowContext(ctx, r.q("SELECT "+userColumns+" FROM {{schema}}.users WHERE id=$1"), identity.UserID))
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, r.q(`
			UPDATE {{schema}}.external_identities SET email=$1, email_verified=$2, last_sign_in_at=$3
			WHERE provider=$4 AND subject=$5`), p.Email, p.EmailVerified, now, p.Provider, p.Subject); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		identity.Email, identity.EmailVerified, identity.LastSignInAt = p.Email, p.EmailVerified, &now
		return &ResolveExternalIdentityResult{User: user, Identity: identity}, nil
	case !errors.Is(err, sql.ErrNoRows):
		return nil, err
	}

	if !p.EmailVerified || p.Email == "" {
		if p.CreateUser {
			return nil, model.ErrEmailNotVerified
		}
		return nil, fmt.Errorf("no user for this sign-in identity: %w", model.ErrNotFound)
	}

	created := false
	user, err := scanUser(tx.QueryRowContext(ctx, r.q("SELECT "+userColumns+
		" FROM {{schema}}.users WHERE lower(email)=lower($1) FOR UPDATE"), p.Email))
	switch {
	case err == nil:
		if user.HasPassword() {
			return nil, &LinkRefusedError{Reason: LinkRefusedHasPassword}
		}
		var otherAccount bool
		if err := tx.QueryRowContext(ctx, r.q(`
			SELECT EXISTS(SELECT 1 FROM {{schema}}.external_identities
			WHERE user_id=$1 AND provider=$2 AND subject<>$3)`), user.ID, p.Provider, p.Subject).Scan(&otherAccount); err != nil {
			return nil, err
		}
		if otherAccount {
			return nil, &LinkRefusedError{Reason: LinkRefusedProviderAccountMismatch}
		}
	case errors.Is(err, sql.ErrNoRows):
		if !p.CreateUser {
			return nil, fmt.Errorf("no user for this sign-in identity: %w", model.ErrNotFound)
		}
		if user, err = r.insertPasswordlessUser(ctx, tx, p.Email, p.DisplayName, now); err != nil {
			return nil, err
		}
		created = true
	default:
		return nil, err
	}

	identity = &model.ExternalIdentity{
		Provider: p.Provider, Subject: p.Subject, UserID: user.ID,
		Email: p.Email, EmailVerified: p.EmailVerified, CreatedAt: now, LastSignInAt: &now,
	}
	if err := r.insertExternalIdentity(ctx, tx, identity); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &ResolveExternalIdentityResult{User: user, Identity: identity, Created: created, Linked: true}, nil
}

// insertPasswordlessUser creates a user with no password (an empty password_hash)
// inside tx and returns the stored row.
func (r *Repository) insertPasswordlessUser(ctx context.Context, tx *sql.Tx, email, displayName string, now time.Time) (*model.User, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("could not generate an id for user: %w", err)
	}
	if _, err := tx.ExecContext(ctx, r.q(`
		INSERT INTO {{schema}}.users (
			id, email, password_hash, display_name, token_version,
			is_enabled, is_locked, failed_login_count, created_at, updated_at
		)
		VALUES ($1, $2, '', $3, 0, true, false, 0, $4, $4)`), id.String(), email, displayName, now); err != nil {
		return nil, err
	}
	return scanUser(tx.QueryRowContext(ctx, r.q("SELECT "+userColumns+" FROM {{schema}}.users WHERE id=$1"), id.String()))
}

func (r *Repository) insertExternalIdentity(ctx context.Context, tx *sql.Tx, e *model.ExternalIdentity) error {
	_, err := tx.ExecContext(ctx, r.q(`
		INSERT INTO {{schema}}.external_identities
		(provider, subject, user_id, email, email_verified, created_at, last_sign_in_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`),
		e.Provider, e.Subject, e.UserID, e.Email, e.EmailVerified, e.CreatedAt, e.LastSignInAt)
	return err
}

// LinkExternalIdentity links (provider, subject) to userID, a user the application
// has authenticated. Linking an identity the user already has refreshes its email
// snapshot. It returns model.ErrNotFound for an unknown user and
// model.ErrIdentityAlreadyLinked when another user has the identity.
func (r *Repository) LinkExternalIdentity(ctx context.Context, userID, provider, subject, email string, emailVerified bool) (*model.ExternalIdentity, error) {
	e, err := r.linkExternalIdentityOnce(ctx, userID, provider, subject, email, emailVerified)
	if isUniqueViolation(err) {
		// A concurrent Link inserted the same identity first; the retry sees whose it is.
		e, err = r.linkExternalIdentityOnce(ctx, userID, provider, subject, email, emailVerified)
	}
	return e, err
}

func (r *Repository) linkExternalIdentityOnce(ctx context.Context, userID, provider, subject, email string, emailVerified bool) (*model.ExternalIdentity, error) {
	tx, err := r.rw.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var lockedID string
	err = tx.QueryRowContext(ctx, r.q("SELECT id FROM {{schema}}.users WHERE id=$1 FOR UPDATE"), userID).Scan(&lockedID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("user not found: %w", model.ErrNotFound)
	}
	if err != nil {
		return nil, err
	}

	e, err := scanExternalIdentity(tx.QueryRowContext(ctx, r.q("SELECT "+externalIdentityColumns+
		" FROM {{schema}}.external_identities WHERE provider=$1 AND subject=$2 FOR UPDATE"), provider, subject))
	switch {
	case err == nil:
		if e.UserID != userID {
			return nil, model.ErrIdentityAlreadyLinked
		}
		if _, err := tx.ExecContext(ctx, r.q(`
			UPDATE {{schema}}.external_identities SET email=$1, email_verified=$2
			WHERE provider=$3 AND subject=$4`), email, emailVerified, provider, subject); err != nil {
			return nil, err
		}
		e.Email, e.EmailVerified = email, emailVerified
	case errors.Is(err, sql.ErrNoRows):
		e = &model.ExternalIdentity{
			Provider: provider, Subject: subject, UserID: userID,
			Email: email, EmailVerified: emailVerified, CreatedAt: time.Now(),
		}
		if err := r.insertExternalIdentity(ctx, tx, e); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return e, nil
}

// UnlinkExternalIdentity removes one of userID's links. A link that does not exist,
// or belongs to another user, is model.ErrNotFound.
func (r *Repository) UnlinkExternalIdentity(ctx context.Context, userID, provider, subject string) error {
	result, err := r.rw.ExecContext(ctx, r.q(
		"DELETE FROM {{schema}}.external_identities WHERE user_id=$1 AND provider=$2 AND subject=$3"),
		userID, provider, subject)
	if err != nil {
		return fmt.Errorf("failed to unlink external identity: %w", err)
	}
	return requireRowsAffected(result, fmt.Errorf("external identity not found: %w", model.ErrNotFound))
}

// GetExternalIdentity returns the link for (provider, subject) from the replica.
func (r *Repository) GetExternalIdentity(ctx context.Context, provider, subject string) (*model.ExternalIdentity, error) {
	e, err := scanExternalIdentity(r.ro.QueryRowContext(ctx, r.q("SELECT "+externalIdentityColumns+
		" FROM {{schema}}.external_identities WHERE provider=$1 AND subject=$2"), provider, subject))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("external identity not found: %w", model.ErrNotFound)
	}
	return e, err
}

// ListExternalIdentities returns userID's links from the replica, by provider and
// then link time.
func (r *Repository) ListExternalIdentities(ctx context.Context, userID string) ([]*model.ExternalIdentity, error) {
	rows, err := r.ro.QueryContext(ctx, r.q("SELECT "+externalIdentityColumns+
		" FROM {{schema}}.external_identities WHERE user_id=$1 ORDER BY provider, created_at, subject"), userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list external identities: %w", err)
	}
	defer func() { _ = rows.Close() }()
	identities := []*model.ExternalIdentity{}
	for rows.Next() {
		e, err := scanExternalIdentity(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan external identity: %w", err)
		}
		identities = append(identities, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating external identities: %w", err)
	}
	return identities, nil
}
