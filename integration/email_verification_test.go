//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"testing"
	"time"

	authkit "github.com/modgudinc/authkit-go"
	"github.com/modgudinc/authkit-go/model"
)

func TestMarkEmailVerified(t *testing.T) {
	db, k, _, adminID := verifiedFixture(t, authkit.SessionDisabled)
	ctx := context.Background()
	users := k.UserService()

	admin, err := users.GetByID(ctx, adminID)
	if err != nil || admin.HasVerifiedEmail() {
		t.Fatalf("a new user starts unverified: %+v, %v", admin, err)
	}
	if err := users.MarkEmailVerified(ctx, adminID); err != nil {
		t.Fatal(err)
	}
	first, err := users.GetByEmail(ctx, "ADMIN@sessions.test")
	if err != nil || first.EmailVerifiedAt == nil {
		t.Fatalf("not marked: %+v, %v", first, err)
	}
	// Marking again keeps the first verification time.
	if err := users.MarkEmailVerified(ctx, adminID); err != nil {
		t.Fatal(err)
	}
	again, err := users.GetByID(ctx, adminID)
	if err != nil || !again.EmailVerifiedAt.Equal(*first.EmailVerifiedAt) {
		t.Fatalf("second mark moved the time: %v, %v", again.EmailVerifiedAt, err)
	}
	listed, err := users.List(ctx, 10, 0)
	if err != nil || len(listed) != 1 || !listed[0].HasVerifiedEmail() {
		t.Fatalf("list: %v", err)
	}
	requireError(t, users.MarkEmailVerified(ctx, "01a11a39-0000-7000-8000-000000000000"), authkit.ErrNotFound)
	requireError(t, users.MarkEmailVerified(ctx, ""), authkit.ErrInvalidInput)

	// An invitation's code is known to whoever created it, so accepting one does not
	// prove the invitee owns the address.
	invitation, err := k.InvitationService().Create(ctx, model.CreateInvitationRequest{
		TenantID: "sessions.test", CreatedBy: adminID, Email: "invitee@sessions.test", Roles: []string{"Member"},
	})
	if err != nil {
		t.Fatal(err)
	}
	inviteeID, created, err := k.InvitationService().Accept(ctx, model.AcceptInvitationRequest{
		Code: invitation.Code, Email: "invitee@sessions.test", DisplayName: "Invitee",
	})
	if err != nil || !created {
		t.Fatalf("accept: %v", err)
	}
	invitee, err := users.GetByID(ctx, inviteeID)
	if err != nil || invitee.HasVerifiedEmail() {
		t.Fatalf("accepting an invitation marked the email verified: %+v, %v", invitee, err)
	}

	// A user Resolve creates from a provider-verified address starts verified.
	res := resolve(t, k, model.ResolveExternalIdentityRequest{Provider: "google", Subject: "g-1", Email: "new@example.test", EmailVerified: true, CreateUser: true})
	if !res.User.HasVerifiedEmail() {
		t.Fatal("Resolve returned an unverified new user")
	}
	if n := countRows(t, db, "SELECT count(*) FROM authkit.users WHERE id=$1 AND email_verified_at IS NOT NULL", res.User.ID); n != 1 {
		t.Fatal("Resolve stored an unverified new user")
	}
}

// The email-code sign-in from docs/verified-sign-in.md, end to end.
func TestEmailCodeSignIn(t *testing.T) {
	_, k, _, _ := verifiedFixture(t, authkit.SessionRequired)
	ctx := context.Background()
	const email, purpose = "Person@Example.test", "sign_in"

	code, err := k.OTPService().Generate(ctx, model.OTPGenerateRequest{Email: email, Purpose: purpose, ExpirationDuration: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	err = k.OTPService().Validate(ctx, model.OTPValidateRequest{Email: email, Code: "not-the-code", Purpose: purpose})
	requireError(t, err, authkit.ErrInvalidOTP)
	if err := k.OTPService().Validate(ctx, model.OTPValidateRequest{Email: email, Code: code.Code, Purpose: purpose}); err != nil {
		t.Fatal(err)
	}
	// The code is used up.
	if err := k.OTPService().Validate(ctx, model.OTPValidateRequest{Email: email, Code: code.Code, Purpose: purpose}); err == nil {
		t.Fatal("a code signed in twice")
	}

	// First sign-in: no user yet, so create one without a password.
	_, err = k.UserService().GetByEmail(ctx, email)
	requireError(t, err, authkit.ErrNotFound)
	userID, err := k.UserService().Create(ctx, model.CreateUserRequest{Email: email, DisplayName: "Person"})
	if err != nil {
		t.Fatal(err)
	}
	if err := k.UserService().MarkEmailVerified(ctx, userID); err != nil {
		t.Fatal(err)
	}
	login := openSession(t, k, model.OpenSessionRequest{UserID: userID, SignInMethod: "email_code"})
	if login.Session.SignInMethod != "email_code" || login.User.HasPassword() {
		t.Fatalf("session: %+v", login.Session)
	}

	// Later the person signs in with Google for the same address: it links.
	res := resolve(t, k, model.ResolveExternalIdentityRequest{Provider: "google", Subject: "g-person", Email: "person@example.test", EmailVerified: true, CreateUser: true})
	if res.User.ID != userID || !res.Linked || res.Created {
		t.Fatalf("Google sign-in did not link to the email-code account: %+v", res)
	}
}

func TestEmailVerificationMigration(t *testing.T) {
	db := openTestDB(t)
	t.Cleanup(func() { applyMigration(t, db, "000001_identity_schema.down.sql"); _ = db.Close() })
	ctx := context.Background()
	applyMigration(t, db, "000001_identity_schema.down.sql")
	applyMigration(t, db, "000001_identity_schema.up.sql")
	// A user from before 000005; the new code cannot read users until it is applied.
	const userID = "01a11a39-0000-7000-8000-000000000005"
	if _, err := db.Exec(`INSERT INTO authkit.users (id, email, display_name, password_hash)
		VALUES ($1, 'old@example.test', 'Old', '')`, userID); err != nil {
		t.Fatal(err)
	}
	k := verifiedKit(t, db, authkit.SessionDisabled, nil)
	_, err := k.UserService().GetByID(ctx, userID)
	requireError(t, err, authkit.ErrInternal)

	applyMigration(t, db, "000005_email_verification.up.sql")
	applyMigration(t, db, "000005_email_verification.up.sql") // idempotent
	user, err := k.UserService().GetByID(ctx, userID)
	if err != nil || user.HasVerifiedEmail() {
		t.Fatalf("an existing user should start unverified: %+v, %v", user, err)
	}
	if err := k.UserService().MarkEmailVerified(ctx, userID); err != nil {
		t.Fatal(err)
	}

	applyMigration(t, db, "000005_email_verification.down.sql")
	applyMigration(t, db, "000005_email_verification.down.sql")
	if n := countRows(t, db, `SELECT count(*) FROM information_schema.columns
		WHERE table_schema='authkit' AND table_name='users' AND column_name='email_verified_at'`); n != 0 {
		t.Fatal("down migration kept the column")
	}
	applyMigration(t, db, "000005_email_verification.up.sql")
	user, err = k.UserService().GetByID(ctx, userID)
	if err != nil || user.HasVerifiedEmail() {
		t.Fatalf("after down and up: %+v, %v", user, err)
	}
}
