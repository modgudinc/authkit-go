// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/internal/repository"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/metrics"
	"github.com/modgudinc/authkit-go/model"
)

// The marker is covered by the stored HMAC. Legacy random base64 tokens cannot
// contain '.', so bound credentials cannot downgrade if their session is missing.
const boundRefreshPrefix = "s1."

type SessionService struct {
	repo   *repository.Repository
	config model.SessionConfig
	logger logger.Logger
}

func NewSessionService(repo *repository.Repository, config model.SessionConfig, log logger.Logger) *SessionService {
	return &SessionService{repo: repo, config: config, logger: ensureLogger(log)}
}

func validSessionReference(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.ContainsRune(value, 0) && utf8.ValidString(value) && utf8.RuneCountInString(value) <= 255
}

func (s *SessionService) enabled() error {
	if s.config.Mode == model.SessionDisabled {
		return model.ErrSessionDisabled
	}
	return nil
}

func (s *SessionService) Get(ctx context.Context, userID, sessionID string) (*model.Session, error) {
	if err := s.enabled(); err != nil {
		return nil, err
	}
	if userID == "" || sessionID == "" {
		return nil, model.ErrInvalidInput
	}
	session, err := s.repo.GetSession(ctx, s.config.Namespace, userID, sessionID)
	return session, sanitizeError(ctx, s.logger, "get session", err)
}

func (s *SessionService) List(ctx context.Context, userID string, limit, offset int) ([]model.Session, error) {
	if err := s.enabled(); err != nil {
		return nil, err
	}
	if userID == "" || limit < 1 || limit > 200 || offset < 0 {
		return nil, model.ErrInvalidInput
	}
	sessions, err := s.repo.ListSessions(ctx, s.config.Namespace, userID, limit, offset)
	return sessions, sanitizeError(ctx, s.logger, "list sessions", err)
}

func (s *SessionService) Revoke(ctx context.Context, userID, sessionID string) error {
	if err := s.enabled(); err != nil {
		return err
	}
	if userID == "" || sessionID == "" {
		return model.ErrInvalidInput
	}
	return sanitizeError(ctx, s.logger, "revoke session", s.repo.RevokeSessions(ctx, s.config.Namespace, userID, sessionID, "", "session_revoked"))
}

func (s *SessionService) RevokeInstallation(ctx context.Context, userID, installationID string) error {
	if err := s.enabled(); err != nil {
		return err
	}
	if userID == "" || !validSessionReference(installationID) {
		return model.ErrInvalidInput
	}
	return sanitizeError(ctx, s.logger, "revoke installation", s.repo.RevokeSessions(ctx, s.config.Namespace, userID, "", installationID, "installation_revoked"))
}

func (s *SessionService) CleanupExpired(ctx context.Context) (int64, error) {
	if err := s.enabled(); err != nil {
		return 0, err
	}
	count, err := s.repo.CleanupSessions(ctx, s.config.Namespace)
	return count, sanitizeError(ctx, s.logger, "cleanup sessions", err)
}

func checkSession(s *model.Session) error {
	now := time.Now()
	if s.RevokedAt != nil || !now.Before(s.ExpiresAt) || !now.Before(s.AbsoluteExpiresAt) {
		return model.ErrSessionRevoked
	}
	return nil
}

func (s *TokenService) checkInstallation(binding *model.InstallationBinding) error {
	if s == nil {
		if binding != nil {
			return model.ErrSessionDisabled
		}
		return nil
	}
	if binding == nil {
		if s.sessionConfig.Mode == model.SessionRequired {
			return model.ErrSessionRequired
		}
		return nil
	}
	if s.sessionConfig.Mode == model.SessionDisabled {
		return model.ErrSessionDisabled
	}
	if !validSessionReference(binding.InstallationID) {
		return model.ErrInvalidInput
	}
	return nil
}

func (s *TokenService) boundRefresh(token string) (bool, error) {
	bound := strings.HasPrefix(token, boundRefreshPrefix)
	if bound && s.sessionConfig.Mode == model.SessionDisabled {
		return false, model.ErrSessionDisabled
	}
	if !bound && s.sessionConfig.Mode == model.SessionRequired {
		return false, model.ErrSessionRequired
	}
	return bound, nil
}

func (s *TokenService) sessionForRefresh(ctx context.Context, token string) (*model.Session, error) {
	bound, err := s.boundRefresh(token)
	if err != nil || !bound {
		return nil, err
	}
	session, err := s.repo.SessionForRefresh(ctx, s.sessionConfig.Namespace, s.hashToken(token))
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "lookup bound session", err)
	}
	if err := checkSession(session); err != nil {
		return nil, err
	}
	return session, nil
}

func (s *TokenService) sessionForClaims(ctx context.Context, claims *model.JWTClaims) (*model.Session, error) {
	if claims.SessionID == "" {
		if s.sessionConfig.Mode == model.SessionRequired {
			return nil, model.ErrSessionRequired
		}
		return nil, nil
	}
	if s.sessionConfig.Mode == model.SessionDisabled {
		return nil, model.ErrSessionDisabled
	}
	session, err := s.repo.GetSession(ctx, s.sessionConfig.Namespace, claims.UserID, claims.SessionID)
	if errors.Is(err, model.ErrNotFound) {
		return nil, model.ErrSessionRevoked
	}
	if err != nil {
		return nil, sanitizeError(ctx, s.logger, "validate session", err)
	}
	if session.TokenVersion != claims.TokenVersion {
		return nil, model.ErrSessionRevoked
	}
	if err := checkSession(session); err != nil {
		return nil, err
	}
	return session, nil
}

// checkOptionalInstallation validates the installation an OpenSession call may
// carry. Unlike checkInstallation, a missing binding is fine in every mode: without
// session support it opens a plain identity session, otherwise a session record
// with no installation.
func (s *TokenService) checkOptionalInstallation(binding *model.InstallationBinding) error {
	if binding == nil {
		return nil
	}
	if s == nil || s.sessionConfig.Mode == model.SessionDisabled {
		return model.ErrSessionDisabled
	}
	if !validSessionReference(binding.InstallationID) {
		return model.ErrInvalidInput
	}
	return nil
}

func (s *TokenService) createBoundSession(ctx context.Context, user *model.User, info *model.SessionInfo, binding *model.InstallationBinding) (string, *model.Session, error) {
	if err := s.checkInstallation(binding); err != nil {
		return "", nil, err
	}
	return s.openBoundSession(ctx, user, info, binding.InstallationID, model.SignInMethodPassword)
}

// openVerifiedSession opens the session for VerifiedLoginService.OpenSession: a
// plain identity session (no record) when session support is disabled, otherwise a
// session record, bound to the installation when one is given. The caller has run
// checkOptionalInstallation.
func (s *TokenService) openVerifiedSession(ctx context.Context, user *model.User, info *model.SessionInfo, binding *model.InstallationBinding, method string) (string, *model.Session, error) {
	if s.sessionConfig.Mode == model.SessionDisabled {
		token, err := s.CreateIdentitySession(ctx, user.ID, info)
		return token, nil, err
	}
	installationID := ""
	if binding != nil {
		installationID = binding.InstallationID
	}
	return s.openBoundSession(ctx, user, info, installationID, method)
}

// openBoundSession creates a session record and its first refresh token in one
// transaction. installationID may be empty for a session with no installation.
func (s *TokenService) openBoundSession(ctx context.Context, user *model.User, info *model.SessionInfo, installationID, method string) (string, *model.Session, error) {
	random, err := s.jwtService.GenerateRefreshToken()
	if err != nil {
		return "", nil, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return "", nil, sanitizeError(ctx, s.logger, "generate session ID", err)
	}
	now := time.Now()
	session := &model.Session{
		ID: id.String(), UserID: user.ID, Namespace: s.sessionConfig.Namespace,
		InstallationID: installationID, SignInMethod: method, TokenVersion: user.TokenVersion,
		CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(s.refreshExpiry),
		AbsoluteExpiresAt: now.Add(s.sessionConfig.AbsoluteLifetime),
	}
	if session.AbsoluteExpiresAt.Before(session.ExpiresAt) {
		session.ExpiresAt = session.AbsoluteExpiresAt
	}
	token := boundRefreshPrefix + random
	ip, agent, name := sessionPointers(info)
	err = s.repo.CreateBoundSession(ctx, user, session, repository.CreateRefreshTokenRequest{
		TokenHash: s.hashToken(token), IPAddress: ip, UserAgent: agent, DeviceName: name,
	})
	if err != nil {
		return "", nil, sanitizeError(ctx, s.logger, "create bound session", err)
	}
	return token, session, nil
}

func (s *TokenService) generateInstallationPair(ctx context.Context, user *model.User, membership *model.Membership, info *model.SessionInfo, binding *model.InstallationBinding) (*model.TokenPairResponse, error) {
	if binding == nil {
		return s.GenerateTokenPair(ctx, user, membership, info)
	}
	refresh, session, err := s.createBoundSession(ctx, user, info, binding)
	if err != nil {
		return nil, err
	}
	access, expires, err := s.mintSessionAccess(user, membership, session)
	if err != nil {
		return nil, err
	}
	return &model.TokenPairResponse{AccessToken: access, RefreshToken: refresh, ExpiresIn: expires}, nil
}

func (s *TokenService) mintSessionAccess(user *model.User, membership *model.Membership, session *model.Session) (string, int64, error) {
	if session == nil {
		return s.MintAccessToken(context.Background(), user, membership)
	}
	if err := checkSession(session); err != nil {
		return "", 0, err
	}
	expiry := time.Now().Add(s.jwtService.GetAccessExpiry())
	if session.ExpiresAt.Before(expiry) {
		expiry = session.ExpiresAt
	}
	// JWT dates have second precision; never round a bound token beyond the cap.
	expiry = expiry.Truncate(time.Second)
	if !time.Now().Before(expiry) {
		return "", 0, model.ErrSessionRevoked
	}
	token, err := s.jwtService.generateAccessToken(user, membership, session.ID, expiry)
	return token, int64(time.Until(expiry).Seconds()), err
}

func (s *TokenService) refreshBoundPair(ctx context.Context, token, tenantID string, info *model.SessionInfo) (*model.TokenPairResponse, error) {
	random, err := s.jwtService.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}
	replacement := boundRefreshPrefix + random
	ip, agent, name := sessionPointers(info)
	user, membership, session, err := s.repo.RotateBoundRefresh(ctx, s.sessionConfig.Namespace, s.hashToken(token), tenantID, repository.CreateRefreshTokenRequest{
		TokenHash: s.hashToken(replacement), ExpiresAt: time.Now().Add(s.refreshExpiry),
		IPAddress: ip, UserAgent: agent, DeviceName: name,
	})
	if err != nil {
		if errors.Is(err, model.ErrRefreshTokenReuse) {
			incMetric(s.metrics, metrics.CounterRefreshReuse)
			s.logger.Warn(ctx, "bound refresh token reuse detected; identity token version invalidated", "error", err)
		}
		return nil, sanitizeError(ctx, s.logger, "rotate bound refresh token", err)
	}
	access, expires, err := s.mintSessionAccess(user, membership, session)
	if err != nil {
		cctx, cancel := cleanupContext(ctx)
		defer cancel()
		if cleanupErr := s.repo.RevokeSessions(cctx, s.sessionConfig.Namespace, user.ID, session.ID, "", "issuance_failed"); cleanupErr != nil {
			s.logger.Error(cctx, "failed to revoke session after issuance failure", "error", cleanupErr)
		}
		return nil, err
	}
	return &model.TokenPairResponse{AccessToken: access, RefreshToken: replacement, ExpiresIn: expires}, nil
}

// LoginWithInstallation authenticates with caller-verified enrollment.
func (s *AuthService) LoginWithInstallation(ctx context.Context, req model.InstallationLoginRequest) (*model.InstallationLoginResponse, error) {
	resp, err := s.login(ctx, req.LoginRequest, &req.Installation)
	if err != nil {
		return nil, err
	}
	session, err := s.tokenService.sessionForRefresh(ctx, resp.RefreshToken)
	if err != nil {
		return nil, err
	}
	return &model.InstallationLoginResponse{LoginResponse: *resp, Session: session}, nil
}

func (s *AuthService) LoginByEmailWithInstallation(ctx context.Context, req model.InstallationLoginByEmailRequest) (*model.InstallationLoginResponse, error) {
	resp, err := s.loginByEmail(ctx, req.LoginByEmailRequest, &req.Installation)
	if err != nil {
		return nil, err
	}
	session, err := s.tokenService.sessionForRefresh(ctx, resp.RefreshToken)
	if err != nil {
		return nil, err
	}
	return &model.InstallationLoginResponse{LoginResponse: *resp, Session: session}, nil
}

func (s *AuthService) ValidateInstallationJWT(ctx context.Context, token string) (*model.InstallationClaims, error) {
	claims, err := s.ValidateJWT(ctx, token)
	if err != nil {
		return nil, err
	}
	session, err := s.tokenService.sessionForClaims(ctx, claims)
	if err != nil {
		return nil, err
	}
	// A session opened without an installation (VerifiedLoginService.OpenSession
	// from a browser, say) is not an installation binding.
	if session == nil || session.InstallationID == "" {
		return nil, model.ErrSessionRequired
	}
	return &model.InstallationClaims{Claims: claims, Session: session}, nil
}
