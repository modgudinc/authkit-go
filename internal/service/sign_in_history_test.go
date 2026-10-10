// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
)

// fakeSignInRecorder keeps the sign-in history in memory.
type fakeSignInRecorder struct {
	events []*model.SignInEvent
	err    error
}

func (f *fakeSignInRecorder) InsertSignInEvent(ctx context.Context, e *model.SignInEvent) error {
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, e)
	return nil
}

// labelMetrics counts increments by "name|label=value".
type labelMetrics map[string]int

func (m labelMetrics) IncCounter(name string, labels ...string) {
	for i := 0; i+1 < len(labels); i += 2 {
		name += "|" + labels[i] + "=" + labels[i+1]
	}
	m[name]++
}

func newRecordingAuthService(repo *fakeAuthRepository) (*AuthService, *fakeSignInRecorder) {
	svc := newTestAuthService(repo)
	rec := &fakeSignInRecorder{}
	svc.signIns = rec
	svc.signInNamespace = "app"
	return svc, rec
}

func onlyEvent(t *testing.T, rec *fakeSignInRecorder) *model.SignInEvent {
	t.Helper()
	if len(rec.events) != 1 {
		t.Fatalf("recorded %d sign-ins, want 1", len(rec.events))
	}
	return rec.events[0]
}

// Every refusal of an existing account is recorded with its reason, and the caller
// still gets the same generic error.
func TestLoginRecordsRefusals(t *testing.T) {
	future := time.Now().Add(time.Hour)
	cases := []struct {
		name     string
		setup    func(u *model.User, repo *fakeAuthRepository)
		password string
		want     string
		wantErr  error
	}{
		{"bad password", func(*model.User, *fakeAuthRepository) {}, "Wrong1!", model.SignInFailureBadPassword, model.ErrInvalidCredentials},
		{"disabled", func(u *model.User, _ *fakeAuthRepository) { u.IsEnabled = false }, "Correct1!", model.SignInFailureAccountDisabled, model.ErrInvalidCredentials},
		{"locked", func(u *model.User, _ *fakeAuthRepository) { u.IsLocked, u.LockedUntil = true, &future }, "Correct1!", model.SignInFailureAccountLocked, model.ErrInvalidCredentials},
		{"no password", func(u *model.User, _ *fakeAuthRepository) { u.PasswordHash = "" }, "Correct1!", model.SignInFailureNoPassword, model.ErrInvalidCredentials},
		{"no membership", func(_ *model.User, repo *fakeAuthRepository) { repo.membership = nil }, "Correct1!", model.SignInFailureNoMembership, model.ErrNoActiveMembership},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user := makeUser(t, "Correct1!")
			repo := &fakeAuthRepository{user: user, membership: makeMembership(user.ID)}
			tc.setup(user, repo)
			svc, rec := newRecordingAuthService(repo)

			_, err := svc.Login(context.Background(), model.LoginRequest{
				Email: user.Email, Password: tc.password, TenantID: testTenantID,
				SessionInfo: &model.SessionInfo{IPAddress: "203.0.113.7:51234", UserAgent: "agent", DeviceName: "laptop"},
			})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
			e := onlyEvent(t, rec)
			if e.UserID != user.ID || e.Succeeded || e.FailureReason != tc.want || e.Method != model.SignInMethodPassword {
				t.Fatalf("recorded %+v, want a %s failure for the user", e, tc.want)
			}
			if e.TenantID != testTenantID || e.Namespace != "app" || e.SessionID != "" {
				t.Fatalf("recorded workspace %q, namespace %q, session %q", e.TenantID, e.Namespace, e.SessionID)
			}
			if e.IPAddress != "203.0.113.7" || e.UserAgent != "agent" || e.DeviceName != "laptop" {
				t.Fatalf("recorded where from as %q, %q, %q", e.IPAddress, e.UserAgent, e.DeviceName)
			}
			if e.ID == "" || e.OccurredAt.IsZero() {
				t.Fatal("an event needs an id and a time")
			}
		})
	}
}

// An email that matches no account has nothing to attach a row to.
func TestLoginUnknownEmailIsNotRecorded(t *testing.T) {
	svc, rec := newRecordingAuthService(&fakeAuthRepository{getByEmailErr: model.ErrNotFound})
	if _, err := svc.LoginByEmail(context.Background(), model.LoginByEmailRequest{Email: "nobody@acme.test", Password: "x"}); !errors.Is(err, model.ErrInvalidCredentials) {
		t.Fatalf("got %v", err)
	}
	if len(rec.events) != 0 {
		t.Fatalf("recorded %d sign-ins for an unknown email", len(rec.events))
	}
}

// The history is best-effort: a failed write changes nothing for the sign-in, and
// is counted so operators can see it.
func TestSignInHistoryWriteFailureIsCounted(t *testing.T) {
	user := makeUser(t, "Correct1!")
	svc, rec := newRecordingAuthService(&fakeAuthRepository{user: user, membership: makeMembership(user.ID)})
	rec.err = errors.New("relation \"sign_in_events\" does not exist")
	m := labelMetrics{}
	svc.metrics = m

	_, err := svc.Login(context.Background(), model.LoginRequest{Email: user.Email, Password: "Wrong1!", TenantID: testTenantID})
	if !errors.Is(err, model.ErrInvalidCredentials) || errors.Is(err, model.ErrInternal) {
		t.Fatalf("a failed history write must not change the outcome: %v", err)
	}
	if got := m[metrics.CounterBestEffortWriteFailure+"|op=record_sign_in"]; got != 1 {
		t.Fatalf("best-effort failure counter = %d, want 1", got)
	}
}

// A client that hangs up after the outcome is decided still leaves its attempt in
// the history.
func TestSignInHistoryIgnoresCancellation(t *testing.T) {
	user := makeUser(t, "Correct1!")
	svc := newTestAuthService(&fakeAuthRepository{user: user})
	rec := &ctxCheckingRecorder{}
	svc.signIns = rec
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	svc.recordSignInFailure(ctx, signIn{method: model.SignInMethodPassword}, user.ID, model.SignInFailureBadPassword)
	if !rec.called || rec.ctxErr != nil {
		t.Fatalf("recorder called %v with context error %v", rec.called, rec.ctxErr)
	}
}

type ctxCheckingRecorder struct {
	called bool
	ctxErr error
}

func (r *ctxCheckingRecorder) InsertSignInEvent(ctx context.Context, e *model.SignInEvent) error {
	r.called, r.ctxErr = true, ctx.Err()
	return nil
}

// Free text from the client is cleaned so the row can always be stored: a NUL byte
// or invalid UTF-8 would otherwise make PostgreSQL refuse it, and keep an
// attacker's attempts out of the history.
func TestSignInHistoryCleansClientText(t *testing.T) {
	user := makeUser(t, "Correct1!")
	svc, rec := newRecordingAuthService(&fakeAuthRepository{user: user})
	longAgent := strings.Repeat("é", 400) // 800 bytes
	svc.recordSignInFailure(context.Background(), signIn{
		method: model.SignInMethodPassword, tenantID: "acme\x00" + strings.Repeat("t", 300),
		info: &model.SessionInfo{IPAddress: "not an address", UserAgent: "bot\x00\xff" + longAgent, DeviceName: "my\x00 laptop"},
	}, user.ID, model.SignInFailureBadPassword)

	e := onlyEvent(t, rec)
	if e.IPAddress != "" {
		t.Fatalf("an address that does not parse must be dropped, got %q", e.IPAddress)
	}
	for name, v := range map[string]string{"user agent": e.UserAgent, "device name": e.DeviceName, "workspace": e.TenantID} {
		if strings.ContainsRune(v, 0) || !utf8.ValidString(v) {
			t.Fatalf("%s %q holds a NUL byte or invalid UTF-8", name, v)
		}
	}
	if len(e.UserAgent) > maxUserAgentBytes || !strings.HasPrefix(e.UserAgent, "botéé") {
		t.Fatalf("user agent cut to %d bytes: %q", len(e.UserAgent), e.UserAgent[:16])
	}
	if e.DeviceName != "my laptop" || utf8.RuneCountInString(e.TenantID) != maxSignInFieldRunes {
		t.Fatalf("device %q, workspace of %d characters", e.DeviceName, utf8.RuneCountInString(e.TenantID))
	}
}

func TestCleanIPAddress(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":           "203.0.113.7",
		" 203.0.113.7 ":         "203.0.113.7",
		"203.0.113.7:51234":     "203.0.113.7",
		"2001:db8::1":           "2001:db8::1",
		"[2001:db8::1]:51234":   "2001:db8::1",
		"fe80::1%eth0":          "fe80::1",
		"":                      "",
		"localhost":             "",
		"203.0.113.7, 10.0.0.1": "",
	} {
		if got := cleanIPAddress(in); got != want {
			t.Errorf("cleanIPAddress(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClipBytesKeepsCharactersWhole(t *testing.T) {
	if got := clipBytes("hé", 2); got != "h" {
		t.Fatalf("clipBytes split a character: %q", got)
	}
	if got := clipBytes("short", 10); got != "short" {
		t.Fatalf("clipBytes changed a short string: %q", got)
	}
}

func TestSignInHistoryServiceValidatesInput(t *testing.T) {
	svc := NewSignInHistoryService(nil, nil)
	ctx := context.Background()
	for _, tc := range []struct {
		user          string
		limit, offset int
	}{{"", 10, 0}, {"u", 0, 0}, {"u", 201, 0}, {"u", 10, -1}} {
		if _, err := svc.List(ctx, tc.user, tc.limit, tc.offset); !errors.Is(err, model.ErrInvalidInput) {
			t.Errorf("List(%q, %d, %d) = %v, want ErrInvalidInput", tc.user, tc.limit, tc.offset, err)
		}
	}
	if _, err := svc.Cleanup(ctx, 0); !errors.Is(err, model.ErrInvalidInput) {
		t.Errorf("Cleanup(0) = %v, want ErrInvalidInput", err)
	}
}
