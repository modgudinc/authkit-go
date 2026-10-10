//go:build integration

// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	authkit "github.com/modgudinc/authkit-go"
	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
)

const passkeyRP = "example.test"

// passkeyFixture is verifiedFixture with the passkey migration applied.
func passkeyFixture(t *testing.T) (*sql.DB, *authkit.AuthKit, *countingMetrics, string) {
	t.Helper()
	db, k, m, userID := verifiedFixture(t, authkit.SessionRequired)
	applyMigration(t, db, "000008_passkeys.up.sql")
	return db, k, m, userID
}

func passkeyUser(t *testing.T, k *authkit.AuthKit, userID, rpID string) *model.PasskeyUser {
	t.Helper()
	pu, err := k.PasskeyService().User(context.Background(), userID, rpID)
	if err != nil {
		t.Fatalf("User: %v", err)
	}
	return pu
}

// registration is a passkey as a WebAuthn library reports it after a verified
// registration ceremony.
func registration(userID string, credentialID string) model.RegisterPasskeyRequest {
	return model.RegisterPasskeyRequest{
		UserID: userID, RPID: passkeyRP, CredentialID: []byte(credentialID),
		PublicKey: []byte("cose-key-" + credentialID), SignCount: 1,
		Transports:   []string{"internal", "hybrid"},
		UserVerified: true, BackupEligible: true, BackupState: true,
		AAGUID:          bytes.Repeat([]byte{0xad}, 16),
		AttestationType: "none", AttestationFormat: "packed",
		AttestationObject: []byte("attestation-object"), AttestationClientDataJSON: []byte(`{"type":"webauthn.create"}`),
		Name: " MacBook ",
	}
}

func register(t *testing.T, k *authkit.AuthKit, req model.RegisterPasskeyRequest) *model.Passkey {
	t.Helper()
	p, err := k.PasskeyService().Register(context.Background(), req)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return p
}

func onlyPasskey(t *testing.T, pu *model.PasskeyUser) *model.Passkey {
	t.Helper()
	if len(pu.Passkeys) != 1 {
		t.Fatalf("got %d passkeys, want 1", len(pu.Passkeys))
	}
	return pu.Passkeys[0]
}

// Each user gets one random handle per relying party, made once and kept.
func TestPasskeyUserHandle(t *testing.T) {
	db, k, _, userID := passkeyFixture(t)
	ctx := context.Background()
	svc := k.PasskeyService()

	first := passkeyUser(t, k, userID, " Example.TEST ")
	if len(first.UserHandle) != 64 || first.User.ID != userID || first.Passkeys == nil || len(first.Passkeys) != 0 {
		t.Fatalf("first call: handle of %d bytes, user %q, passkeys %v", len(first.UserHandle), first.User.ID, first.Passkeys)
	}
	if bytes.Contains(first.UserHandle, []byte(userID)) {
		t.Fatal("the handle must not carry the user id")
	}
	again := passkeyUser(t, k, userID, passkeyRP)
	if !bytes.Equal(again.UserHandle, first.UserHandle) {
		t.Fatal("the handle changed between calls")
	}
	if other := passkeyUser(t, k, userID, "other.test"); bytes.Equal(other.UserHandle, first.UserHandle) {
		t.Fatal("two relying parties share a handle")
	}
	otherUser, err := k.UserService().Create(ctx, model.CreateUserRequest{Email: "other@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if theirs := passkeyUser(t, k, otherUser, passkeyRP); bytes.Equal(theirs.UserHandle, first.UserHandle) {
		t.Fatal("two users share a handle")
	}

	_, err = svc.User(ctx, "01a11a39-0000-7000-8000-000000000000", passkeyRP)
	requireError(t, err, authkit.ErrNotFound)
	for _, rp := range []string{"", "exa mple.test", ".example.test", "example.test.", "example..test", "exämple.test", strings.Repeat("a", 254)} {
		_, err := svc.User(ctx, userID, rp)
		requireError(t, err, authkit.ErrInvalidInput)
	}
	_, err = svc.User(ctx, "", passkeyRP)
	requireError(t, err, authkit.ErrInvalidInput)

	// Concurrent first calls agree on one handle.
	raceUser, err := k.UserService().Create(ctx, model.CreateUserRequest{Email: "race@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	handles := make([][]byte, 8)
	errs := make([]error, 8)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range handles {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			var pu *model.PasskeyUser
			if pu, errs[i] = svc.User(ctx, raceUser, passkeyRP); pu != nil {
				handles[i] = pu.UserHandle
			}
		}(i)
	}
	close(start)
	wg.Wait()
	for i := range handles {
		if errs[i] != nil || !bytes.Equal(handles[i], handles[0]) {
			t.Fatalf("concurrent first calls disagree: %v", errs[i])
		}
	}
	if n := countRows(t, db, "SELECT count(*) FROM authkit.passkey_users WHERE user_id=$1", raceUser); n != 1 {
		t.Fatalf("%d handles for one user at one RP", n)
	}
}

// A registered passkey comes back whole for the next ceremony, found by its user
// or by the handle a discoverable sign-in returns.
func TestPasskeyRegisterAndFind(t *testing.T) {
	_, k, _, userID := passkeyFixture(t)
	ctx := context.Background()
	svc := k.PasskeyService()
	pu := passkeyUser(t, k, userID, passkeyRP)

	req := registration(userID, "cred-1")
	stored := register(t, k, req)
	if stored.Name != "MacBook" || stored.CreatedAt.IsZero() || stored.LastUsedAt != nil {
		t.Fatalf("registered: %+v", stored)
	}

	found, err := svc.UserByHandle(ctx, passkeyRP, pu.UserHandle)
	if err != nil {
		t.Fatalf("UserByHandle: %v", err)
	}
	if found.User.ID != userID || !bytes.Equal(found.UserHandle, pu.UserHandle) {
		t.Fatalf("found %q with another handle", found.User.ID)
	}
	p := onlyPasskey(t, found)
	if p.RPID != passkeyRP || !bytes.Equal(p.CredentialID, req.CredentialID) || p.UserID != userID || p.Name != "MacBook" ||
		!bytes.Equal(p.PublicKey, req.PublicKey) || p.SignCount != 1 || !slices.Equal(p.Transports, req.Transports) ||
		!p.UserVerified || !p.BackupEligible || !p.BackupState || !bytes.Equal(p.AAGUID, req.AAGUID) ||
		p.AttestationType != "none" || p.AttestationFormat != "packed" ||
		!bytes.Equal(p.AttestationObject, req.AttestationObject) || !bytes.Equal(p.AttestationClientDataJSON, req.AttestationClientDataJSON) ||
		!p.CreatedAt.Equal(stored.CreatedAt) {
		t.Fatalf("the record did not round-trip: %+v", p)
	}

	// The fields a WebAuthn library may leave empty read back empty.
	bare := register(t, k, model.RegisterPasskeyRequest{UserID: userID, RPID: passkeyRP, CredentialID: []byte("cred-bare"), PublicKey: []byte("k")})
	if bare.Transports == nil || len(bare.Transports) != 0 {
		t.Fatalf("transports: %v", bare.Transports)
	}
	again := passkeyUser(t, k, userID, passkeyRP)
	if len(again.Passkeys) != 2 || !bytes.Equal(again.Passkeys[0].CredentialID, []byte("cred-1")) {
		t.Fatalf("passkeys should list oldest first: %d", len(again.Passkeys))
	}
	if b := again.Passkeys[1]; b.Transports == nil || len(b.Transports) != 0 || len(b.AAGUID) != 0 || len(b.AttestationObject) != 0 || b.SignCount != 0 || b.UserVerified {
		t.Fatalf("bare passkey: %+v", b)
	}

	for _, handle := range [][]byte{bytes.Repeat([]byte{1}, 64), pu.UserHandle[:63]} {
		_, err = svc.UserByHandle(ctx, passkeyRP, handle)
		requireError(t, err, authkit.ErrNotFound)
	}
	_, err = svc.UserByHandle(ctx, "other.test", pu.UserHandle)
	requireError(t, err, authkit.ErrNotFound)
	_, err = svc.UserByHandle(ctx, passkeyRP, nil)
	requireError(t, err, authkit.ErrInvalidInput)

	// WebAuthn requires a credential ID be registered once, to anyone.
	otherUser, err := k.UserService().Create(ctx, model.CreateUserRequest{Email: "other@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	passkeyUser(t, k, otherUser, passkeyRP)
	for _, who := range []string{userID, otherUser} {
		_, err = svc.Register(ctx, registration(who, "cred-1"))
		requireError(t, err, authkit.ErrPasskeyAlreadyRegistered)
	}
	// The longest credential ID WebAuthn allows fits.
	longest := registration(userID, string(bytes.Repeat([]byte{0xfe}, 1023)))
	register(t, k, longest)

	// The same id at another relying party is another credential.
	passkeyUser(t, k, userID, "other.test")
	elsewhere := registration(userID, "cred-1")
	elsewhere.RPID = "other.test"
	register(t, k, elsewhere)

	// Register needs the user's handle at the RP ID, which User makes.
	noHandle := registration(userID, "cred-2")
	noHandle.RPID = "third.test"
	_, err = svc.Register(ctx, noHandle)
	requireError(t, err, authkit.ErrNotFound)
	_, err = svc.Register(ctx, registration("01a11a39-0000-7000-8000-000000000000", "cred-3"))
	requireError(t, err, authkit.ErrNotFound)
}

// A sign-in writes its counter and flags back; a counter that did not go up is
// refused and changes nothing.
func TestPasskeyRecordUse(t *testing.T) {
	_, k, m, userID := passkeyFixture(t)
	ctx := context.Background()
	svc := k.PasskeyService()
	passkeyUser(t, k, userID, passkeyRP)
	register(t, k, registration(userID, "counted"))
	use := func(credentialID string, count uint32, uv, bs bool) error {
		return svc.RecordUse(ctx, model.PasskeyUseRequest{
			UserID: userID, RPID: " EXAMPLE.test ", CredentialID: []byte(credentialID),
			SignCount: count, UserVerified: uv, BackupState: bs,
		})
	}
	stored := func(credentialID string) *model.Passkey {
		t.Helper()
		for _, p := range passkeyUser(t, k, userID, passkeyRP).Passkeys {
			if string(p.CredentialID) == credentialID {
				return p
			}
		}
		t.Fatalf("no passkey %q", credentialID)
		return nil
	}

	if err := use("counted", 5, false, false); err != nil {
		t.Fatalf("RecordUse: %v", err)
	}
	p := stored("counted")
	if p.SignCount != 5 || !p.UserVerified || p.BackupState || p.LastUsedAt == nil {
		t.Fatalf("after a sign-in: count %d, user verified %v, backed up %v, last used %v", p.SignCount, p.UserVerified, p.BackupState, p.LastUsedAt)
	}
	lastUsed := *p.LastUsedAt
	for _, count := range []uint32{5, 4, 0} {
		requireError(t, use("counted", count, true, true), authkit.ErrPasskeyCloned)
	}
	if p := stored("counted"); p.SignCount != 5 || p.BackupState || !p.LastUsedAt.Equal(lastUsed) {
		t.Fatalf("a refused sign-in changed the passkey: %+v", p)
	}
	if got := m.get(metrics.CounterWebAuthnCloneWarning); got != 3 {
		t.Fatalf("clone warnings counted %d, want 3", got)
	}
	if err := use("counted", 6, false, true); err != nil {
		t.Fatalf("RecordUse: %v", err)
	}
	if p := stored("counted"); p.SignCount != 6 || !p.BackupState {
		t.Fatalf("after a later sign-in: %+v", p)
	}

	// A passkey that reports no counter (0) keeps working while it reports none.
	zero := registration(userID, "uncounted")
	zero.SignCount, zero.UserVerified = 0, false
	register(t, k, zero)
	for range 2 {
		if err := use("uncounted", 0, false, false); err != nil {
			t.Fatalf("a passkey without a counter: %v", err)
		}
	}
	if p := stored("uncounted"); p.UserVerified {
		t.Fatal("user verification must not appear from nowhere")
	}
	if err := use("uncounted", 0, true, false); err != nil {
		t.Fatal(err)
	}
	if p := stored("uncounted"); !p.UserVerified {
		t.Fatal("user verification was not recorded")
	}
	if err := use("uncounted", 3, false, false); err != nil {
		t.Fatal(err)
	}
	requireError(t, use("uncounted", 0, false, false), authkit.ErrPasskeyCloned)

	// Only the owner's passkey, at its relying party.
	otherUser, err := k.UserService().Create(ctx, model.CreateUserRequest{Email: "other@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	requireError(t, svc.RecordUse(ctx, model.PasskeyUseRequest{UserID: otherUser, RPID: passkeyRP, CredentialID: []byte("counted"), SignCount: 99}), authkit.ErrNotFound)
	requireError(t, svc.RecordUse(ctx, model.PasskeyUseRequest{UserID: userID, RPID: "other.test", CredentialID: []byte("counted"), SignCount: 99}), authkit.ErrNotFound)
	requireError(t, svc.RecordUse(ctx, model.PasskeyUseRequest{UserID: userID, RPID: passkeyRP, SignCount: 99}), authkit.ErrInvalidInput)

	// Sign-ins reporting the same count at once: one wins, the others are refused.
	for count := uint32(7); count < 27; count++ {
		results := make([]error, 8)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				results[i] = use("counted", count, false, false)
			}(i)
		}
		close(start)
		wg.Wait()
		won := 0
		for _, err := range results {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, authkit.ErrPasskeyCloned):
				t.Fatalf("concurrent sign-in: %v", err)
			}
		}
		if won != 1 {
			t.Fatalf("%d sign-ins recorded count %d", won, count)
		}
	}
}

func TestPasskeyListRenameRemove(t *testing.T) {
	db, k, _, userID := passkeyFixture(t)
	ctx := context.Background()
	svc := k.PasskeyService()
	pu := passkeyUser(t, k, userID, passkeyRP)
	register(t, k, registration(userID, "phone"))
	register(t, k, registration(userID, "key"))
	otherUser, err := k.UserService().Create(ctx, model.CreateUserRequest{Email: "other@example.test"})
	if err != nil {
		t.Fatal(err)
	}

	list, err := svc.List(ctx, userID, passkeyRP)
	if err != nil || len(list) != 2 || string(list[0].CredentialID) != "phone" {
		t.Fatalf("List: %d passkeys, %v", len(list), err)
	}
	if none, err := svc.List(ctx, otherUser, passkeyRP); err != nil || none == nil || len(none) != 0 {
		t.Fatalf("a user with no passkeys: %v, %v", none, err)
	}
	if n := countRows(t, db, "SELECT count(*) FROM authkit.passkey_users WHERE user_id=$1", otherUser); n != 0 {
		t.Fatal("List must not create a handle")
	}

	if err := svc.Rename(ctx, userID, passkeyRP, []byte("phone"), "  Pixel  "); err != nil {
		t.Fatal(err)
	}
	if list, _ := svc.List(ctx, userID, passkeyRP); list[0].Name != "Pixel" {
		t.Fatalf("renamed to %q", list[0].Name)
	}
	requireError(t, svc.Rename(ctx, otherUser, passkeyRP, []byte("phone"), "mine"), authkit.ErrNotFound)
	requireError(t, svc.Rename(ctx, userID, passkeyRP, []byte("phone"), strings.Repeat("é", 256)), authkit.ErrValueTooLong)
	requireError(t, svc.Rename(ctx, userID, passkeyRP, []byte("phone"), "a\x00b"), authkit.ErrInvalidInput)

	requireError(t, svc.Remove(ctx, otherUser, passkeyRP, []byte("phone")), authkit.ErrNotFound)
	if err := svc.Remove(ctx, userID, passkeyRP, []byte("phone")); err != nil {
		t.Fatal(err)
	}
	requireError(t, svc.Remove(ctx, userID, passkeyRP, []byte("phone")), authkit.ErrNotFound)
	// A removed passkey stops working at once.
	found, err := svc.UserByHandle(ctx, passkeyRP, pu.UserHandle)
	if err != nil || len(found.Passkeys) != 1 || string(found.Passkeys[0].CredentialID) != "key" {
		t.Fatalf("after removal: %v", err)
	}
	requireError(t, svc.RecordUse(ctx, model.PasskeyUseRequest{UserID: userID, RPID: passkeyRP, CredentialID: []byte("phone"), SignCount: 9}), authkit.ErrNotFound)
	// The handle outlives the passkeys, so a new one carries the same handle.
	if err := svc.Remove(ctx, userID, passkeyRP, []byte("key")); err != nil {
		t.Fatal(err)
	}
	if again := passkeyUser(t, k, userID, passkeyRP); !bytes.Equal(again.UserHandle, pu.UserHandle) || len(again.Passkeys) != 0 {
		t.Fatal("the handle changed after the passkeys were removed")
	}

	// Deleting the user deletes its handles and passkeys.
	register(t, k, registration(userID, "last"))
	if _, err := db.Exec("DELETE FROM authkit.users WHERE id=$1", userID); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"passkey_users", "passkeys"} {
		if n := countRows(t, db, "SELECT count(*) FROM authkit."+table+" WHERE user_id=$1", userID); n != 0 {
			t.Fatalf("%s rows outlived their user", table)
		}
	}
}

func TestPasskeyMigration(t *testing.T) {
	db, k, _, userID := verifiedFixture(t, authkit.SessionDisabled)
	ctx := context.Background()
	// Without the migration the calls fail cleanly, without leaking SQL.
	_, err := k.PasskeyService().User(ctx, userID, passkeyRP)
	requireError(t, err, authkit.ErrInternal)
	_, err = k.PasskeyService().Register(ctx, registration(userID, "c"))
	requireError(t, err, authkit.ErrInternal)

	applyMigration(t, db, "000008_passkeys.up.sql")
	applyMigration(t, db, "000008_passkeys.up.sql") // idempotent
	passkeyUser(t, k, userID, passkeyRP)
	register(t, k, registration(userID, "c"))
	applyMigration(t, db, "000008_passkeys.down.sql")
	applyMigration(t, db, "000008_passkeys.down.sql")
	applyMigration(t, db, "000008_passkeys.up.sql")
	if n := countRows(t, db, "SELECT count(*) FROM authkit.passkeys"); n != 0 {
		t.Fatal("down migration kept passkeys")
	}
}
