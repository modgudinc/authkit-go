// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/modgudinc/authkit-go/model"
)

func TestNormalizeRPID(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":         "example.com",
		" Login.Example.COM ": "login.example.com",
		"localhost":           "localhost",
		"xn--bcher-kva.de":    "xn--bcher-kva.de",
	} {
		if got, err := normalizeRPID(in); err != nil || got != want {
			t.Errorf("normalizeRPID(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", " ", ".example.com", "example.com.", "example..com", "exa mple.com", "example.com:443", "https://example.com", "bücher.de", strings.Repeat("a", 254)} {
		if _, err := normalizeRPID(in); !errors.Is(err, model.ErrInvalidInput) {
			t.Errorf("normalizeRPID(%q) = %v, want ErrInvalidInput", in, err)
		}
	}
}

// Register refuses what WebAuthn or the columns cannot hold before it touches the
// database (the service here has none).
func TestPasskeyRegisterValidatesInput(t *testing.T) {
	svc := NewPasskeyService(nil, nil, nil)
	valid := func() model.RegisterPasskeyRequest {
		return model.RegisterPasskeyRequest{UserID: "u", RPID: "example.com", CredentialID: []byte("id"), PublicKey: []byte("key")}
	}
	cases := []struct {
		name   string
		change func(*model.RegisterPasskeyRequest)
		want   error
	}{
		{"no user", func(r *model.RegisterPasskeyRequest) { r.UserID = "" }, model.ErrInvalidInput},
		{"bad RP ID", func(r *model.RegisterPasskeyRequest) { r.RPID = "example.com/login" }, model.ErrInvalidInput},
		{"no credential ID", func(r *model.RegisterPasskeyRequest) { r.CredentialID = nil }, model.ErrInvalidInput},
		{"long credential ID", func(r *model.RegisterPasskeyRequest) { r.CredentialID = make([]byte, 1024) }, model.ErrInvalidInput},
		{"no public key", func(r *model.RegisterPasskeyRequest) { r.PublicKey = nil }, model.ErrInvalidInput},
		{"short AAGUID", func(r *model.RegisterPasskeyRequest) { r.AAGUID = make([]byte, 15) }, model.ErrInvalidInput},
		{"backed up, not eligible", func(r *model.RegisterPasskeyRequest) { r.BackupState = true }, model.ErrInvalidInput},
		{"too many transports", func(r *model.RegisterPasskeyRequest) { r.Transports = make([]string, 17) }, model.ErrInvalidInput},
		{"empty transport", func(r *model.RegisterPasskeyRequest) { r.Transports = []string{"usb", ""} }, model.ErrInvalidInput},
		{"odd transport", func(r *model.RegisterPasskeyRequest) { r.Transports = []string{"USB"} }, model.ErrInvalidInput},
		{"long transport", func(r *model.RegisterPasskeyRequest) { r.Transports = []string{strings.Repeat("a", 33)} }, model.ErrInvalidInput},
		{"NUL in name", func(r *model.RegisterPasskeyRequest) { r.Name = "my\x00key" }, model.ErrInvalidInput},
		{"invalid UTF-8 name", func(r *model.RegisterPasskeyRequest) { r.Name = "key\xff" }, model.ErrInvalidInput},
		{"long name", func(r *model.RegisterPasskeyRequest) { r.Name = strings.Repeat("é", 256) }, model.ErrValueTooLong},
		{"bad attestation type", func(r *model.RegisterPasskeyRequest) { r.AttestationType = "basic full" }, model.ErrInvalidInput},
		{"bad attestation format", func(r *model.RegisterPasskeyRequest) { r.AttestationFormat = "-packed" }, model.ErrInvalidInput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := valid()
			tc.change(&req)
			if _, err := svc.Register(context.Background(), req); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestPasskeyCallsValidateInput(t *testing.T) {
	svc := NewPasskeyService(nil, nil, nil)
	ctx := context.Background()
	id := []byte("id")
	checks := map[string]error{}
	_, checks["User without a user"] = svc.User(ctx, "", "example.com")
	_, checks["User with a bad RP ID"] = svc.User(ctx, "u", "")
	_, checks["UserByHandle without a handle"] = svc.UserByHandle(ctx, "example.com", nil)
	_, checks["UserByHandle with a bad RP ID"] = svc.UserByHandle(ctx, "a..b", []byte("h"))
	checks["RecordUse without a credential"] = svc.RecordUse(ctx, model.PasskeyUseRequest{UserID: "u", RPID: "example.com"})
	checks["RecordUse without a user"] = svc.RecordUse(ctx, model.PasskeyUseRequest{RPID: "example.com", CredentialID: id})
	_, checks["List without a user"] = svc.List(ctx, "", "example.com")
	checks["Rename with a long id"] = svc.Rename(ctx, "u", "example.com", bytes.Repeat([]byte{1}, 1024), "n")
	checks["Remove without a credential"] = svc.Remove(ctx, "u", "example.com", nil)
	for name, err := range checks {
		if !errors.Is(err, model.ErrInvalidInput) {
			t.Errorf("%s: got %v, want ErrInvalidInput", name, err)
		}
	}
}
