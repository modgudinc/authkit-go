// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

// SessionInfo contains metadata about the client session
type SessionInfo struct {
	IPAddress  string `json:"ip_address"`
	UserAgent  string `json:"user_agent"`
	DeviceName string `json:"device_name"`
}

// RefreshTokenReuseError is returned when an already-consumed refresh token is
// presented again (reuse/theft). It carries the affected user and token family so
// callers can log/alert with identifying context, and it unwraps to
// ErrRefreshTokenReuse — so errors.Is(err, ErrRefreshTokenReuse) still matches and
// the error continues to flow through the public sanitizeError boundary unchanged.
// Extract the IDs with errors.As(err, &model.RefreshTokenReuseError{}).
type RefreshTokenReuseError struct {
	UserID   string
	FamilyID string
}

func (e *RefreshTokenReuseError) Error() string {
	return "authkit: refresh token reuse detected (user " + e.UserID + ", family " + e.FamilyID + ")"
}

// Unwrap lets errors.Is(err, ErrRefreshTokenReuse) match this typed error.
func (e *RefreshTokenReuseError) Unwrap() error { return ErrRefreshTokenReuse }
