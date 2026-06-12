// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/modgudinc/authkit-go/logger"
	"github.com/modgudinc/authkit-go/model"
)

// clockSkewLeeway is the tolerance applied to time-based claim checks (exp/iat)
// so that small clock differences between issuing and validating hosts do not
// spuriously reject otherwise-valid tokens.
const clockSkewLeeway = 30 * time.Second

// JWTService handles JWT token generation and validation
type JWTService struct {
	accessSecret  string
	refreshSecret string
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

// NewJWTService creates a new JWTService instance
//
// Parameters:
//   - accessSecret: Secret key for signing access tokens (required)
//   - refreshSecret: Secret key for signing refresh tokens (optional, used for HMAC if needed)
//   - accessExpiry: Access token expiration duration (e.g., 15 minutes)
//   - refreshExpiry: Refresh token expiration duration (e.g., 7 days)
//   - logger: Optional logger for structured logging
//   - opts: Optional settings such as WithIssuer / WithAudience
func NewJWTService(
	accessSecret string,
	refreshSecret string,
	accessExpiry time.Duration,
	refreshExpiry time.Duration,
	logger logger.Logger,
	opts ...JWTOption,
) *JWTService {
	s := &JWTService{
		accessSecret:  accessSecret,
		refreshSecret: refreshSecret,
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
		logger:        logger,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// GenerateAccessToken generates a signed JWT access token for a user
//
// Parameters:
//   - user: User model containing ID, email, tenant, roles, token version
//
// # Returns a signed JWT string or error
//
// The JWT contains custom claims:
//   - user_id: User UUID (string representation)
//   - email: User email address
//   - tenant_id: Tenant identifier
//   - roles: Array of user roles
//   - token_version: For invalidating all tokens when incremented
//   - sub: Subject (user_id)
//   - iat: Issued at timestamp
//   - exp: Expiration timestamp
//
// Example:
//
//	token, err := jwtService.GenerateAccessToken(user)
//	if err != nil {
//	    return fmt.Errorf("failed to generate token: %w", err)
//	}
//	// Return token to client
func (s *JWTService) GenerateAccessToken(user *model.User) (string, error) {
	if s.logger != nil {
		s.logger.Info("Generating access token",
			"user_id", user.ID.String(),
			"email", maskEmail(user.Email),
			"tenant_id", user.TenantID,
		)
	}

	now := time.Now()
	expiresAt := now.Add(s.accessExpiry)

	claims := model.JWTClaims{
		UserID:       user.ID.String(),
		Email:        user.Email,
		TenantID:     user.TenantID,
		Roles:        user.Roles,
		TokenVersion: user.TokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.Must(uuid.NewV7()).String(), // jti: unique per token, for log correlation / future denylist
			Subject:   user.ID.String(),
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

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(s.accessSecret))
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to sign JWT token", "error", err.Error())
		}
		return "", fmt.Errorf("failed to sign JWT token: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("Access token generated successfully",
			"user_id", user.ID.String(),
			"expires_at", expiresAt.Format(time.RFC3339),
		)
	}

	return signedToken, nil
}

// ValidateAccessToken validates a JWT access token and extracts claims
//
// Parameters:
//   - tokenString: JWT token string to validate
//
// # Returns parsed model.JWTClaims or error if validation fails
//
// Validation includes:
//   - Signature verification using HMAC-SHA256
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
	// Pin the exact signing algorithm, require an expiration, and allow a small
	// clock-skew leeway. WithValidMethods is the canonical defense against
	// algorithm-confusion / "alg:none" attacks (the keyfunc also checks the family).
	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(clockSkewLeeway),
	}
	if s.issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(s.issuer))
	}
	if s.audience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(s.audience))
	}

	token, err := jwt.ParseWithClaims(tokenString, &model.JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.accessSecret), nil
	}, parserOpts...)
	if err != nil {
		// Validation failures are driven by untrusted input; log at Warn to avoid
		// error-level log floods from clients spamming invalid tokens.
		if s.logger != nil {
			s.logger.Warn("Failed to parse JWT token", "error", err.Error())
		}
		// Wrap the sentinel (not the raw jwt-lib error) so callers using this
		// service directly can errors.Is(err, authkit.ErrInvalidToken), matching
		// AuthService.ValidateJWT. The underlying cause is already logged above.
		return nil, fmt.Errorf("invalid token: %w", model.ErrInvalidToken)
	}

	claims, ok := token.Claims.(*model.JWTClaims)
	if !ok || !token.Valid {
		if s.logger != nil {
			s.logger.Warn("Invalid JWT claims or token")
		}
		return nil, fmt.Errorf("invalid token claims: %w", model.ErrInvalidToken)
	}

	if s.logger != nil {
		s.logger.Info("JWT token validated successfully",
			"user_id", claims.UserID,
			"tenant_id", claims.TenantID,
		)
	}

	return claims, nil
}

// GenerateRefreshToken generates a cryptographically secure refresh token
//
// Returns a base64-encoded random token string (32 bytes = 44 characters)
//
// Note: Refresh tokens are NOT JWTs. They are random tokens stored in the database
// with a SHA256 hash. This enables single-use refresh tokens and rotation.
//
// Flow:
//  1. Generate 32 random bytes using crypto/rand
//  2. Encode to base64 for safe transmission
//  3. Store SHA256 hash in database (not the plaintext token)
//  4. Return plaintext token to client (only time it's visible)
//
// Example:
//
//	refreshToken, err := jwtService.GenerateRefreshToken()
//	if err != nil {
//	    return fmt.Errorf("failed to generate refresh token: %w", err)
//	}
//	// Store SHA256(refreshToken) in database
//	// Return refreshToken to client
func (s *JWTService) GenerateRefreshToken() (string, error) {
	if s.logger != nil {
		s.logger.Info("Generating refresh token")
	}

	// Generate 32 random bytes
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		if s.logger != nil {
			s.logger.Error("Failed to generate random bytes", "error", err.Error())
		}
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base64 for safe transmission
	token := base64.URLEncoding.EncodeToString(randomBytes)

	if s.logger != nil {
		s.logger.Info("Refresh token generated successfully")
	}

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
