// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// Freeze existing request/response shapes independently of the new wrappers.
var (
	_ = SessionInfo{"", "", ""}
	_ = LoginRequest{"", "", "", nil}
	_ = LoginByEmailRequest{"", "", "", nil}
	_ = RefreshRequest{"", "", nil}
	_ = TokenPairResponse{"", "", 0}
)

func TestSessionClaimJSON(t *testing.T) {
	for _, raw := range []string{`{"user_id":"user"}`, `{"sid":"session","user_id":"user"}`} {
		var c JWTClaims
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatal(err)
		}
		if c.UserID != "user" {
			t.Fatal("identity claim changed")
		}
	}
	encoded, err := json.Marshal(JWTClaims{UserID: "user"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "\"sid\"") {
		t.Fatal("legacy JSON gained sid")
	}
	// Existing consumers can still embed the public claims and decode extensions.
	var extended struct {
		JWTClaims
		Custom string `json:"custom"`
	}
	if err := json.Unmarshal([]byte(`{"user_id":"user","custom":"value"}`), &extended); err != nil {
		t.Fatal(err)
	}
	if extended.UserID != "user" || extended.Custom != "value" {
		t.Fatal("embedded consumer claims lost fields")
	}
}
