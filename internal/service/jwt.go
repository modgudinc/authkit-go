// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/model"
)

// clockSkewLeeway is the tolerance applied to the time-based expiry check (exp)
// so that small clock differences between issuing and validating hosts do not
// spuriously reject otherwise-valid tokens. iat is stamped but informational only
// (not validated), and nbf is never issued, so neither is leeway-adjusted.
const clockSkewLeeway = 30 * time.Second

// JWTService handles JWT token generation and validation
type JWTService struct {
	sessionMode  model.SessionMode
	accessSecret string // HS256; signs only when keys has no signing key
	// keys holds the asymmetric keys, or nil. A token with a "kid" header is
	// checked against the key it names; one without is checked as HS256.
	keys          *AccessKeys
	validMethods  []string
	accessExpiry  time.Duration
	refreshExpiry time.Duration
	logger        logger.Logger

	// issuer/audience are optional. When set, they are stamped onto generated
	// access tokens and required during validation.
	issuer   string
	audience string
}

// JWTOption configures optional JWTService behavior.
type JWTOption func(*JWTService)

// Keep strict sid decoding internal. Adding UnmarshalJSON to the public
// JWTClaims would change how consumers' structs embedding it decode fields.
type parsedAccessClaims struct{ model.JWTClaims }

func (c *parsedAccessClaims) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &c.JWTClaims); err != nil {
		return err
	}
	var marker struct {
		SessionID json.RawMessage `json:"sid"`
	}
	if err := json.Unmarshal(data, &marker); err != nil {
		return err
	}
	if len(marker.SessionID) > 0 && c.SessionID == "" {
		return fmt.Errorf("sid must be a non-empty string")
	}
	return nil
}

func WithSessionMode(mode model.SessionMode) JWTOption {
	return func(s *JWTService) { s.sessionMode = mode }
}

// WithIssuer sets the JWT "iss" claim on generated tokens and requires it to
// match during validation. Empty string (the default) disables issuer handling.
func WithIssuer(issuer string) JWTOption {
	return func(s *JWTService) { s.issuer = issuer }
}

// WithAudience sets the JWT "aud" claim on generated tokens and requires it to
// match during validation. Empty string (the default) disables audience handling.
func WithAudience(audience string) JWTOption {
	return func(s *JWTService) { s.audience = audience }
}

// WithAccessKeys adds asymmetric keys. With a signing key, new tokens are signed
// with it and carry its key id, and the HS256 secret (if any) only validates
// tokens signed before the switch. Verification keys are accepted either way.
func WithAccessKeys(keys *AccessKeys) JWTOption {
	return func(s *JWTService) { s.keys = keys }
}

// NewJWTService creates a new JWTService instance
//
// Parameters:
//   - accessSecret: HS256 secret for access tokens; may be empty with WithAccessKeys
//   - accessExpiry: Access token expiration duration (e.g., 15 minutes)
//   - refreshExpiry: Refresh token expiration duration (e.g., 7 days)
//   - logger: Optional logger for structured logging
//   - opts: Optional settings such as WithIssuer / WithAudience
func NewJWTService(
	accessSecret string,
	accessExpiry time.Duration,
	refreshExpiry time.Duration,
	logger logger.Logger,
	opts ...JWTOption,
) *JWTService {
	s := &JWTService{
		accessSecret:  accessSecret,
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
		logger:        ensureLogger(logger),
	}
	for _, opt := range opts {
		opt(s)
	}
	// Accept exactly the algorithms of the configured keys.
	if s.accessSecret != "" {
		s.validMethods = append(s.validMethods, jwt.SigningMethodHS256.Alg())
	}
	if s.keys != nil {
		s.validMethods = append(s.validMethods, s.keys.algorithms()...)
	}
	if s.validMethods == nil {
		s.validMethods = []string{}
	}
	return s
}

// GenerateAccessToken generates a signed, WORKSPACE-SCOPED JWT access token for a
// user's membership.
//
// Parameters:
//   - user: the global identity (ID, Email, TokenVersion)
//   - membership: the active membership the token is scoped to (TenantID, Roles,
//     and the per-membership TokenVersion)
//
// Both MUST be complete, freshly loaded records. The identity fields (user_id,
// email, token_version) come from user; the workspace fields (tenant_id, roles,
// membership_token_version) come from membership. They are copied verbatim into the
// signed claims, so a hand-built or partially populated record — e.g. one left with
// a zero TokenVersion — mints a token that AuthService.ValidateJWT immediately
// treats as revoked once it no longer matches the stored versions. The high-level
// AuthService flows load both for you; this caveat applies when calling the
// JWT/Token services directly.
//
// # Returns a signed JWT string or error
//
// The JWT contains custom claims:
//   - user_id: User UUID (string representation)
//   - email: User email address
//   - tenant_id: Active workspace (from the membership)
//   - roles: Roles in the active workspace (from the membership)
//   - token_version: identity token_version (users.token_version)
//   - membership_token_version: per-workspace token_version (memberships.token_version)
//   - sub: Subject (user_id)
//   - iat / exp: Issued-at / expiration timestamps
//
// Example:
//
//	token, err := jwtService.GenerateAccessToken(user, membership)
//	if err != nil {
//	    return fmt.Errorf("failed to generate token: %w", err)
//	}
//	// Return token to client
func (s *JWTService) GenerateAccessToken(user *model.User, membership *model.Membership) (string, error) {
	if s.sessionMode == model.SessionRequired {
		return "", model.ErrSessionRequired
	}
	return s.generateAccessToken(user, membership, "", time.Now().Add(s.accessExpiry))
}

func (s *JWTService) generateAccessToken(user *model.User, membership *model.Membership, sessionID string, expiresAt time.Time) (string, error) {
	s.logger.Info(context.Background(), "Generating access token",
		"user_id", user.ID,
		"email", maskEmail(user.Email),
		"tenant_id", membership.TenantID,
	)

	now := time.Now()

	claims := model.JWTClaims{
		SessionID:              sessionID,
		UserID:                 user.ID,
		Email:                  user.Email,
		TenantID:               membership.TenantID,
		Roles:                  membership.Roles,
		TokenVersion:           user.TokenVersion,
		MembershipTokenVersion: membership.TokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.Must(uuid.NewV7()).String(), // jti: unique per token, for log correlation / future denylist
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	if s.issuer != "" {
		claims.Issuer = s.issuer
	}
	if s.audience != "" {
		claims.Audience = jwt.ClaimStrings{s.audience}
	}

	signedToken, err := s.sign(claims)
	if err != nil {
		s.logger.Error(context.Background(), "Failed to sign JWT token", "error", err.Error())
		return "", fmt.Errorf("failed to sign JWT token: %w", err)
	}

	s.logger.Info(context.Background(), "Access token generated successfully",
		"user_id", user.ID,
		"expires_at", expiresAt.Format(time.RFC3339),
	)

	return signedToken, nil
}

// sign signs claims with the signing key, stamping its key id, or with the HS256
// secret (and no key id) when there is no signing key.
func (s *JWTService) sign(claims model.JWTClaims) (string, error) {
	if s.keys == nil || s.keys.signing == nil {
		if s.accessSecret == "" {
			return "", errors.New("no access-token signing key is configured")
		}
		return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.accessSecret))
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod(s.keys.signing.alg), claims)
	token.Header["kid"] = s.keys.signing.id
	signingInput, err := token.SigningString()
	if err != nil {
		return "", err
	}
	signature, err := s.keys.sign(signingInput)
	if err != nil {
		return "", err
	}
	return signingInput + "." + token.EncodeSegment(signature), nil
}

// ValidateAccessToken validates a JWT access token and extracts claims
//
// Parameters:
//   - tokenString: JWT token string to validate
//
// # Returns parsed model.JWTClaims or error if validation fails
//
// Validation includes:
//   - Signature verification: a token with a "kid" header against the configured
//     key with that id, in that key's algorithm only; a token without one as HS256
//     against the access secret, when one is configured
//   - Expiration check
//   - Claims parsing
//
// Example:
//
//	claims, err := jwtService.ValidateAccessToken(tokenFromHeader)
//	if err != nil {
//	    // Token is invalid or expired
//	    return fmt.Errorf("unauthorized: %w", err)
//	}
//	// Use claims.UserID, claims.TenantID, etc.
func (s *JWTService) ValidateAccessToken(tokenString string) (*model.JWTClaims, error) {
	// Pin the configured signing algorithms, require an expiration, and allow a
	// small clock-skew leeway. WithValidMethods is the canonical defense against
	// algorithm-confusion / "alg:none" attacks; the keyfunc also pins each key to
	// its own algorithm.
	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods(s.validMethods),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(clockSkewLeeway),
	}
	if s.issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(s.issuer))
	}
	if s.audience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(s.audience))
	}

	token, err := jwt.ParseWithClaims(tokenString, &parsedAccessClaims{}, func(token *jwt.Token) (interface{}, error) {
		if kid, ok := token.Header["kid"]; ok {
			return s.keys.verificationKey(token, kid)
		}
		// authkit never puts a key id on HS256 tokens, and only HS256 goes without one.
		if s.accessSecret == "" || token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("token has no key id")
		}
		return []byte(s.accessSecret), nil
	}, parserOpts...)
	if err != nil {
		// Validation failures are driven by untrusted input; log at Warn to avoid
		// error-level log floods from clients spamming invalid tokens.
		s.logger.Warn(context.Background(), "Failed to parse JWT token", "error", err.Error())
		// Wrap the sentinel (not the raw jwt-lib error) so callers using this
		// service directly can errors.Is(err, authkit.ErrInvalidToken), matching
		// AuthService.ValidateJWT. The underlying cause is already logged above.
		return nil, fmt.Errorf("invalid token: %w", model.ErrInvalidToken)
	}

	claims, ok := token.Claims.(*parsedAccessClaims)
	if !ok || !token.Valid {
		s.logger.Warn(context.Background(), "Invalid JWT claims or token")
		return nil, fmt.Errorf("invalid token claims: %w", model.ErrInvalidToken)
	}
	if claims.SessionID != "" {
		if _, err := uuid.Parse(claims.SessionID); err != nil {
			return nil, model.ErrInvalidToken
		}
		if s.sessionMode == model.SessionDisabled {
			return nil, model.ErrSessionDisabled
		}
	} else if s.sessionMode == model.SessionRequired {
		return nil, model.ErrSessionRequired
	}

	s.logger.Info(context.Background(), "JWT token validated successfully",
		"user_id", claims.UserID,
		"tenant_id", claims.TenantID,
	)

	return &claims.JWTClaims, nil
}

// GenerateRefreshToken generates a cryptographically secure refresh token
//
// Returns a base64-encoded random token string (32 bytes = 44 characters)
//
// Note: Refresh tokens are NOT JWTs. They are random tokens stored in the database
// with an HMAC-SHA256 hash. This enables single-use refresh tokens and rotation.
//
// Flow:
//  1. Generate 32 random bytes using crypto/rand
//  2. Encode to base64 for safe transmission
//  3. Store the HMAC-SHA256 hash in database (not the plaintext token)
//  4. Return plaintext token to client (only time it's visible)
//
// Example:
//
//	refreshToken, err := jwtService.GenerateRefreshToken()
//	if err != nil {
//	    return fmt.Errorf("failed to generate refresh token: %w", err)
//	}
//	// Store HMAC-SHA256(refreshToken) in database (via TokenService)
//	// Return refreshToken to client
func (s *JWTService) GenerateRefreshToken() (string, error) {
	s.logger.Info(context.Background(), "Generating refresh token")

	// Generate 32 random bytes
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		s.logger.Error(context.Background(), "Failed to generate random bytes", "error", err.Error())
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base64 for safe transmission
	token := base64.URLEncoding.EncodeToString(randomBytes)

	s.logger.Info(context.Background(), "Refresh token generated successfully")

	return token, nil
}

// GetAccessExpiry returns the configured access token expiration duration
func (s *JWTService) GetAccessExpiry() time.Duration {
	return s.accessExpiry
}

// GetRefreshExpiry returns the configured refresh token expiration duration
func (s *JWTService) GetRefreshExpiry() time.Duration {
	return s.refreshExpiry
}
