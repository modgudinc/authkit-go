// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
)

const (
	// maxUserAgentBytes bounds a recorded user agent. It comes from the client, and
	// failed attempts are recorded before anyone has signed in.
	maxUserAgentBytes = 512
	// maxSignInFieldRunes bounds the other recorded free-text fields, which are
	// VARCHAR(255) columns.
	maxSignInFieldRunes = 255
	// signInWriteTimeout bounds a history write, which outlives the request's own
	// cancellation.
	signInWriteTimeout = 5 * time.Second
)

// signInRecorder stores sign-in history; *repository.Repository implements it.
type signInRecorder interface {
	InsertSignInEvent(ctx context.Context, e *model.SignInEvent) error
}

// AuthOption configures optional AuthService behavior.
type AuthOption func(*AuthService)

// WithSignInHistory records every sign-in attempt on an existing account in repo's
// sign_in_events (Config.RecordSignIns; migration 000007), tagged with namespace.
func WithSignInHistory(repo *repository.Repository, namespace string) AuthOption {
	return func(s *AuthService) {
		s.signIns = repo
		s.signInNamespace = namespace
	}
}

// signIn describes a sign-in attempt for the history: how the person signed in,
// the workspace they asked for, and where they signed in from.
type signIn struct {
	method       string
	tenantID     string
	installation *model.InstallationBinding
	info         *model.SessionInfo
}

// recordSignInFailure records a refused sign-in on an existing account.
func (s *AuthService) recordSignInFailure(ctx context.Context, attempt signIn, userID, reason string) {
	s.recordSignIn(ctx, attempt, userID, reason, attempt.tenantID, nil)
}

// recordSignInSuccess records a sign-in that opened a session. tenantID is the
// workspace it selected ("" for none); session is the session record, if any.
func (s *AuthService) recordSignInSuccess(ctx context.Context, attempt signIn, userID, tenantID string, session *model.Session) {
	s.recordSignIn(ctx, attempt, userID, "", tenantID, session)
}

// recordSignIn writes one history row when RecordSignIns is on. It is best-effort,
// like last_login: the sign-in's outcome stands whether or not the row is written,
// and a failed write is logged and counted.
func (s *AuthService) recordSignIn(ctx context.Context, attempt signIn, userID, failure, tenantID string, session *model.Session) {
	if s.signIns == nil {
		return
	}
	id, err := uuid.NewV7()
	if err != nil {
		s.signInNotRecorded(ctx, userID, err)
		return
	}
	event := &model.SignInEvent{
		ID: id.String(), UserID: userID, OccurredAt: time.Now(), Method: attempt.method,
		Succeeded: failure == "", FailureReason: failure,
		Namespace: s.signInNamespace, TenantID: clipText(tenantID, maxSignInFieldRunes),
	}
	if session != nil {
		event.SessionID = session.ID
	}
	if attempt.installation != nil {
		event.InstallationID = attempt.installation.InstallationID
	}
	if info := attempt.info; info != nil {
		event.IPAddress = cleanIPAddress(info.IPAddress)
		event.UserAgent = clipBytes(cleanText(info.UserAgent), maxUserAgentBytes)
		event.DeviceName = clipText(info.DeviceName, maxSignInFieldRunes)
	}
	// Write even when the request was cancelled after the outcome was decided: a
	// client that hangs up must not keep its failed attempt out of the history.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), signInWriteTimeout)
	defer cancel()
	if err := s.signIns.InsertSignInEvent(writeCtx, event); err != nil {
		s.signInNotRecorded(ctx, userID, err)
	}
}

func (s *AuthService) signInNotRecorded(ctx context.Context, userID string, err error) {
	s.logger.Error(ctx, "Failed to record sign-in", "user_id", userID, "error", err.Error())
	incMetric(s.metrics, metrics.CounterBestEffortWriteFailure, "op", "record_sign_in")
}

// signInFailureReason maps an account or workspace refusal to its history reason,
// or "" for an error the history does not record.
func signInFailureReason(err error) string {
	switch {
	case errors.Is(err, model.ErrAccountDisabled):
		return model.SignInFailureAccountDisabled
	case errors.Is(err, model.ErrAccountLocked):
		return model.SignInFailureAccountLocked
	case errors.Is(err, model.ErrNoActiveMembership):
		return model.SignInFailureNoMembership
	}
	return ""
}

// cleanIPAddress returns the address in ip, or "" when it does not parse. It accepts
// "host:port" (an http.Request's RemoteAddr) and drops an IPv6 zone, which INET
// cannot store.
func cleanIPAddress(ip string) string {
	ip = strings.TrimSpace(ip)
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		addrPort, portErr := netip.ParseAddrPort(ip)
		if portErr != nil {
			return ""
		}
		addr = addrPort.Addr()
	}
	return addr.WithZone("").String()
}

// cleanText drops what PostgreSQL text cannot store: NUL bytes and invalid UTF-8.
// Without it, a client could keep its attempts out of the history by sending one.
func cleanText(s string) string {
	return strings.ReplaceAll(strings.ToValidUTF8(s, ""), "\x00", "")
}

// clipText cleans s and cuts it to at most n characters.
func clipText(s string, n int) string {
	s = cleanText(s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// clipBytes cuts valid UTF-8 s to at most n bytes without splitting a character.
func clipBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// SignInHistoryService reads the sign-in history that Config.RecordSignIns records
// (migration 000007). The embedding application must authorize the actor before
// passing a target userID.
type SignInHistoryService struct {
	repo   *repository.Repository
	logger logger.Logger
}

func NewSignInHistoryService(repo *repository.Repository, log logger.Logger) *SignInHistoryService {
	return &SignInHistoryService{repo: repo, logger: ensureLogger(log)}
}

// List returns a page of the user's sign-in attempts, newest first, across every
// application sharing the identity database. limit is 1 to 200.
func (s *SignInHistoryService) List(ctx context.Context, userID string, limit, offset int) ([]*model.SignInEvent, error) {
	if userID == "" || limit < 1 || limit > 200 || offset < 0 {
		return nil, model.ErrInvalidInput
	}
	events, err := s.repo.ListSignInEvents(ctx, userID, limit, offset)
	return events, sanitizeError(ctx, s.logger, "list sign-in history", err)
}

// Cleanup deletes sign-in history older than olderThan, which must be positive, and
// returns the number of rows removed. Run it periodically: the history otherwise
// grows for the life of the deployment.
func (s *SignInHistoryService) Cleanup(ctx context.Context, olderThan time.Duration) (int64, error) {
	if olderThan <= 0 {
		return 0, fmt.Errorf("sign-in history retention period must be positive (got %s): %w", olderThan, model.ErrInvalidInput)
	}
	n, err := s.repo.CleanupSignInEvents(ctx, time.Now().Add(-olderThan))
	return n, sanitizeError(ctx, s.logger, "cleanup sign-in history", err)
}
