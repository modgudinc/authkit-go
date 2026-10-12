//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	authkit "github.com/modgudinc/authkit-go"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/model"
)

// txFixture is a schema with sessions.test, its admin (admin@sessions.test, password
// ValidPass1!), a pending invitation of invitee@sessions.test as a Member, and an
// outbox table of the application's own beside authkit's.
func txFixture(t *testing.T) (*sql.DB, *authkit.AuthKit, string, string) {
	t.Helper()
	db, k, _, adminID := verifiedFixture(t, authkit.SessionDisabled)
	if _, err := db.Exec(`CREATE TABLE authkit.app_outbox (kind text NOT NULL, user_id text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	invitation, err := k.InvitationService().Create(context.Background(), model.CreateInvitationRequest{
		TenantID: "sessions.test", CreatedBy: adminID, Email: "invitee@sessions.test", Roles: []string{"Member"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return db, k, adminID, invitation.Code
}

func accept(ctx context.Context, k *authkit.AuthKit, code string) (string, error) {
	userID, _, err := k.InvitationService().Accept(ctx, model.AcceptInvitationRequest{
		Code: code, Email: "invitee@sessions.test", DisplayName: "Invitee",
	})
	return userID, err
}

func record(ctx context.Context, tx *sql.Tx, kind, userID string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO authkit.app_outbox (kind, user_id) VALUES ($1, $2)`, kind, userID)
	return err
}

var errUndo = errors.New("undo")

func TestInTxCommitsAuthkitsChangeWithTheCallers(t *testing.T) {
	db, k, _, code := txFixture(t)
	ctx := context.Background()

	var invitee string
	err := k.InTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		userID, err := accept(ctx, k, code)
		if err != nil {
			return err
		}
		invitee = userID
		// Reads in the transaction see what it wrote, and nothing outside it does yet.
		m, err := k.MembershipService().Get(ctx, userID, "sessions.test")
		if err != nil || m.Status != model.MembershipActive {
			t.Errorf("the transaction's own read: %+v, %v", m, err)
		}
		if n := countRows(t, db, "SELECT count(*) FROM authkit.memberships WHERE user_id=$1", userID); n != 0 {
			t.Errorf("the membership is visible before the commit")
		}
		return record(ctx, tx, "invitation accepted", userID)
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, db, "SELECT count(*) FROM authkit.memberships WHERE user_id=$1 AND status='active'", invitee); n != 1 {
		t.Fatal("the membership did not commit")
	}
	if n := countRows(t, db, "SELECT count(*) FROM authkit.app_outbox WHERE kind='invitation accepted' AND user_id=$1", invitee); n != 1 {
		t.Fatal("the caller's row did not commit")
	}
}

func TestInTxRollsAuthkitsChangeBackWithTheCallers(t *testing.T) {
	db, k, _, code := txFixture(t)
	ctx := context.Background()

	err := k.InTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		userID, err := accept(ctx, k, code)
		if err != nil {
			return err
		}
		if err := record(ctx, tx, "invitation accepted", userID); err != nil {
			return err
		}
		return errUndo
	})
	if !errors.Is(err, errUndo) {
		t.Fatalf("InTx returned %v", err)
	}
	if n := countRows(t, db, "SELECT count(*) FROM authkit.users WHERE email='invitee@sessions.test'"); n != 0 {
		t.Fatal("the invitee's account outlived the rollback")
	}
	if n := countRows(t, db, "SELECT current_uses FROM authkit.invitations WHERE code=$1", code); n != 0 {
		t.Fatal("the invitation stayed used")
	}
	if n := countRows(t, db, "SELECT count(*) FROM authkit.app_outbox"); n != 0 {
		t.Fatal("the caller's row outlived the rollback")
	}
	// The invitation still works.
	if _, err := accept(ctx, k, code); err != nil {
		t.Fatal(err)
	}
}

// A step that fails where authkit would have used a transaction of its own rolls back
// to its savepoint, and the caller's transaction carries on.
func TestAFailedStepLeavesTheCallersTransactionUsable(t *testing.T) {
	db, k, adminID, code := txFixture(t)
	ctx := context.Background()

	err := k.InTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, _, err := k.InvitationService().Accept(ctx, model.AcceptInvitationRequest{Code: code, Email: "someone@else.test"})
		requireError(t, err, authkit.ErrInvitationInvalid)
		// The tenant's last admin cannot be removed.
		requireError(t, k.MembershipService().RemoveGuarded(ctx, adminID, "sessions.test", "Admin"), authkit.ErrLastRoleHolder)
		userID, err := accept(ctx, k, code)
		if err != nil {
			return err
		}
		return record(ctx, tx, "invitation accepted", userID)
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, db, "SELECT count(*) FROM authkit.app_outbox"); n != 1 {
		t.Fatal("the caller's row did not commit")
	}
	if n := countRows(t, db, "SELECT count(*) FROM authkit.memberships WHERE user_id=$1 AND status='active'", adminID); n != 1 {
		t.Fatal("the refused removal changed the admin's membership")
	}
}

// Removing someone and signing them out everywhere commit together, with the record
// of it, or not at all.
func TestRemovalAndSignOutCommitTogether(t *testing.T) {
	db, k, adminID, code := txFixture(t)
	ctx := context.Background()
	invitee, err := accept(ctx, k, code)
	if err != nil {
		t.Fatal(err)
	}
	session, err := k.VerifiedLoginService().OpenSession(ctx, model.OpenSessionRequest{UserID: invitee, SignInMethod: "email", TenantID: "sessions.test"})
	if err != nil {
		t.Fatal(err)
	}

	remove := func(ctx context.Context, tx *sql.Tx) error {
		if err := k.MembershipService().RemoveGuarded(ctx, invitee, "sessions.test", "Admin"); err != nil {
			return err
		}
		if err := k.AuthService().LogoutAll(ctx, invitee); err != nil {
			return err
		}
		return record(ctx, tx, "person removed", invitee)
	}
	err = k.InTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if err := remove(ctx, tx); err != nil {
			return err
		}
		return errUndo
	})
	if !errors.Is(err, errUndo) {
		t.Fatalf("InTx returned %v", err)
	}
	refreshed, err := k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: session.RefreshToken, TenantID: "sessions.test"})
	if err != nil {
		t.Fatalf("a rolled-back removal signed the person out: %v", err)
	}

	if err := k.InTx(ctx, remove); err != nil {
		t.Fatal(err)
	}
	if _, err := k.AuthService().RefreshToken(ctx, model.RefreshRequest{RefreshToken: refreshed.RefreshToken, TenantID: "sessions.test"}); err == nil {
		t.Fatal("a removed person refreshed")
	}
	if n := countRows(t, db, "SELECT count(*) FROM authkit.app_outbox WHERE kind='person removed'"); n != 1 {
		t.Fatal("the removal's record did not commit")
	}
	if n := countRows(t, db, "SELECT count(*) FROM authkit.memberships WHERE user_id=$1 AND status='active'", adminID); n != 1 {
		t.Fatal("the admin lost their membership")
	}
}

// What a refused sign-in records stays recorded when the caller rolls back.
func TestSignInsCommitOnTheirOwn(t *testing.T) {
	db, k, adminID, _ := txFixture(t)
	ctx := context.Background()

	err := k.InTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := k.AuthService().Login(ctx, model.LoginRequest{Email: "admin@sessions.test", Password: "wrong", TenantID: "sessions.test"})
		requireError(t, err, authkit.ErrInvalidCredentials)
		return errUndo
	})
	if !errors.Is(err, errUndo) {
		t.Fatalf("InTx returned %v", err)
	}
	if n := countRows(t, db, "SELECT failed_login_count FROM authkit.users WHERE id=$1", adminID); n != 1 {
		t.Fatalf("the failed attempt was rolled back with the caller: count %d", n)
	}
}

// WithTx takes a transaction the caller began and leaves committing it to them.
func TestWithTxLeavesTheCommitToTheCaller(t *testing.T) {
	db, k, _, code := txFixture(t)
	ctx := context.Background()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	userID, err := accept(authkit.WithTx(ctx, tx), k, code)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, db, "SELECT count(*) FROM authkit.memberships WHERE user_id=$1", userID); n != 1 {
		t.Fatal("the membership did not commit with the caller's transaction")
	}
	// A context without the transaction runs on the pool again.
	if _, err := k.UserService().GetByID(repository.Detach(authkit.WithTx(ctx, tx)), userID); err != nil {
		t.Fatal(err)
	}
}
