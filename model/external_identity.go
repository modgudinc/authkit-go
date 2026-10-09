// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "time"

// ExternalIdentity links one account at an outside sign-in provider (Google,
// GitHub, an enterprise OIDC issuer) to one authkit user. The provider plus the
// provider's stable user id (Subject) identify it; the email is only the address
// the provider last reported, kept for display and audit. It never changes the
// user's own email.
type ExternalIdentity struct {
	// Provider is the application's lowercase name for the provider, e.g. "google".
	Provider string `json:"provider"`
	// Subject is the provider's stable, case-sensitive user id: the OIDC "sub"
	// claim, or GitHub's numeric user id. Never an email or a username.
	Subject string `json:"subject"`
	UserID  string `json:"user_id"`
	// Email and EmailVerified are what the provider last reported.
	Email         string     `json:"email,omitempty"`
	EmailVerified bool       `json:"email_verified"`
	CreatedAt     time.Time  `json:"created_at"`
	LastSignInAt  *time.Time `json:"last_sign_in_at,omitempty"`
}

// ResolveExternalIdentityRequest describes a sign-in the application has already
// verified with the provider (ExternalIdentityService.Resolve).
type ResolveExternalIdentityRequest struct {
	// Provider is the application's name for the provider; it is lowercased and must
	// be 1 to 64 letters, digits, '.', '_', ':' or '-'. Use one name per provider
	// configuration ("google", "github", "oidc:acme").
	Provider string
	// Subject is the provider's stable user id (the OIDC "sub" claim, GitHub's
	// numeric id). Never pass an email or a username here.
	Subject string
	// Email is the address the provider reported, if any.
	Email string
	// EmailVerified must be true only when the provider asserts that it verified
	// Email and the application trusts that assertion for this provider. An
	// unverified email is stored for display but never used to find a user.
	EmailVerified bool
	// DisplayName is used only when a user is created.
	DisplayName string
	// CreateUser creates a user without a password, its email marked verified, when
	// none matches. It needs a verified Email; otherwise Resolve returns
	// ErrEmailNotVerified.
	CreateUser bool
}

// ResolvedExternalIdentity is the user a provider sign-in belongs to. Created is
// true when Resolve created the user; Linked is true when Resolve linked the
// identity to the user during this call (a new or an existing user).
type ResolvedExternalIdentity struct {
	User     *User             `json:"user"`
	Identity *ExternalIdentity `json:"identity"`
	Created  bool              `json:"created"`
	Linked   bool              `json:"linked"`
}

// LinkExternalIdentityRequest links a provider identity to a user the application
// has authenticated (ExternalIdentityService.Link), for example from an account
// settings page or after ErrIdentityLinkRequired. UserID must come from the
// application's own session, never from a request body.
type LinkExternalIdentityRequest struct {
	UserID        string
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
}
