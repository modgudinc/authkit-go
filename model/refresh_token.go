// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

// SessionInfo contains metadata about the client session
type SessionInfo struct {
	IPAddress  string `json:"ip_address"`
	UserAgent  string `json:"user_agent"`
	DeviceName string `json:"device_name"`
}
