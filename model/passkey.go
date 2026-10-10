// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package model

import "time"

// Passkey is a WebAuthn credential (a passkey or a security key) registered to a
// user at one relying party (RPID). It holds the WebAuthn credential record the
// application needs to verify the next sign-in with it, plus a label and when it
// was registered and last used. Requires migration 000008.
type Passkey struct {
	// RPID is the WebAuthn relying party ID the credential was created for, such as
	// "example.com". A credential works only at its RP ID.
	RPID string `json:"rp_id"`
	// CredentialID is the authenticator's id for the credential, echoed in every
	// sign-in with it. It is unique at its RP ID.
	CredentialID []byte `json:"credential_id"`
	UserID       string `json:"user_id"`
	// Name is the label the person gave the passkey ("MacBook", "YubiKey"); it may
	// be empty.
	Name string `json:"name"`
	// PublicKey is the credential's public key as a COSE_Key.
	PublicKey []byte `json:"public_key"`
	// SignCount is the authenticator's signature counter at the last sign-in. Many
	// passkeys always report 0.
	SignCount uint32 `json:"sign_count"`
	// Transports are the authenticator's transport hints ("internal", "hybrid",
	// "usb", ...), as the browser reported them at registration.
	Transports []string `json:"transports"`
	// UserVerified is the credential record's uvInitialized flag: whether the
	// credential has verified its user (a PIN or biometric) in a ceremony that
	// counted. Once true it stays true.
	UserVerified bool `json:"user_verified"`
	// BackupEligible reports whether the credential can be synced or backed up (a
	// multi-device passkey). It never changes.
	BackupEligible bool `json:"backup_eligible"`
	// BackupState reports whether the credential was backed up at its last use.
	BackupState bool `json:"backup_state"`
	// AAGUID identifies the authenticator's model (16 bytes), or is empty.
	AAGUID []byte `json:"aaguid,omitempty"`
	// AttestationType and AttestationFormat describe the registration's attestation
	// ("none", "packed", ...), and AttestationObject and AttestationClientDataJSON
	// are its raw bytes. The application stores them to check the authenticator
	// against metadata later; they are empty when it chose not to.
	AttestationType           string     `json:"attestation_type,omitempty"`
	AttestationFormat         string     `json:"attestation_format,omitempty"`
	AttestationObject         []byte     `json:"attestation_object,omitempty"`
	AttestationClientDataJSON []byte     `json:"attestation_client_data_json,omitempty"`
	CreatedAt                 time.Time  `json:"created_at"`
	LastUsedAt                *time.Time `json:"last_used_at,omitempty"`
}

// PasskeyUser is what a WebAuthn ceremony at one relying party needs to know
// about a user (PasskeyService.User and UserByHandle): the user, their WebAuthn
// user handle there, and the passkeys they registered there, oldest first.
type PasskeyUser struct {
	User *User `json:"user"`
	// UserHandle is the user's WebAuthn user handle at the RP ID: 64 random bytes,
	// the same for every passkey the user registers there. Pass it as the user id
	// of registration options; a discoverable sign-in returns it.
	UserHandle []byte     `json:"user_handle"`
	Passkeys   []*Passkey `json:"passkeys"`
}

// RegisterPasskeyRequest stores a credential the application has verified in a
// WebAuthn registration ceremony (PasskeyService.Register). The ceremony's options
// must have used the user's UserHandle at RPID from PasskeyService.User.
type RegisterPasskeyRequest struct {
	// UserID must come from the application's own signed-in session, never from a
	// request body.
	UserID string
	// RPID is the relying party ID the ceremony ran for; it is lowercased.
	RPID string
	// CredentialID is 1 to 1,023 bytes.
	CredentialID []byte
	// PublicKey is the credential's COSE_Key; it is required.
	PublicKey []byte
	// SignCount is the counter the authenticator reported at registration.
	SignCount uint32
	// Transports are at most 16 transport hints, each 1 to 32 of [a-z0-9_-].
	Transports []string
	// UserVerified, BackupEligible and BackupState are the registration's flags. A
	// credential cannot be backed up (BackupState) without being eligible.
	UserVerified   bool
	BackupEligible bool
	BackupState    bool
	// AAGUID is empty or 16 bytes.
	AAGUID []byte
	// AttestationType and AttestationFormat are empty or a lowercase name;
	// AttestationObject and AttestationClientDataJSON are stored as given.
	AttestationType           string
	AttestationFormat         string
	AttestationObject         []byte
	AttestationClientDataJSON []byte
	// Name is the person's label for the passkey, up to 255 characters; it may be
	// empty.
	Name string
}

// PasskeyUseRequest records a sign-in the application verified with a passkey
// (PasskeyService.RecordUse): the credential record's new state after the
// ceremony.
type PasskeyUseRequest struct {
	// UserID is the user the ceremony verified, RPID the relying party ID it ran
	// for, and CredentialID the passkey it used.
	UserID       string
	RPID         string
	CredentialID []byte
	// SignCount is the signature counter the authenticator reported.
	SignCount uint32
	// UserVerified is the credential's uvInitialized flag after the ceremony. It is
	// only ever set: false leaves a verified passkey verified.
	UserVerified bool
	// BackupState is the backup state the authenticator reported.
	BackupState bool
}
