// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/modgudinc/authkit-go/model"
)

// Passkey repository methods (migration 000008). A user has one WebAuthn user
// handle per relying party ID (passkey_users) and any number of passkeys there
// (passkeys), keyed by (rp_id, credential_id).
//
// - PasskeyUserHandle          - A user's handle at an RP ID, created on first use (primary)
// - PasskeyUserIDByHandle      - The user a handle names (primary)
// - ListPasskeysFromPrimary    - A user's passkeys at an RP ID, for a ceremony (primary)
// - ListPasskeys               - The same, for display (replica)
// - InsertPasskey              - Store a registered passkey
// - RecordPasskeyUse           - Write a sign-in's counter and flags back, refusing a counter that went backwards
// - RenamePasskey, DeletePasskey - One of a user's passkeys
//
// Ceremony reads use the primary, so a passkey stops working the moment it is
// deleted.

// passkeyUserHandleBytes is the size of a generated user handle: the 64 random bytes
// WebAuthn recommends, and its maximum.
const passkeyUserHandleBytes = 64

const passkeyColumns = "rp_id, credential_id, user_id, name, public_key, sign_count, transports, user_verified, " +
	"backup_eligible, backup_state, aaguid, attestation_type, attestation_format, attestation_object, " +
	"attestation_client_data_json, created_at, last_used_at"

func scanPasskey(row scannable) (*model.Passkey, error) {
	var p model.Passkey
	var transports []byte
	if err := row.Scan(&p.RPID, &p.CredentialID, &p.UserID, &p.Name, &p.PublicKey, &p.SignCount, &transports,
		&p.UserVerified, &p.BackupEligible, &p.BackupState, &p.AAGUID, &p.AttestationType, &p.AttestationFormat,
		&p.AttestationObject, &p.AttestationClientDataJSON, &p.CreatedAt, &p.LastUsedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(transports, &p.Transports); err != nil {
		return nil, fmt.Errorf("failed to decode passkey transports: %w", err)
	}
	if p.Transports == nil {
		p.Transports = []string{}
	}
	return &p, nil
}

func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == foreignKeyViolation
}

// PasskeyUserHandle returns userID's WebAuthn user handle at rpID, creating a random
// one on first use. Concurrent first calls agree on one handle. It returns
// model.ErrNotFound for an unknown user.
func (r *Repository) PasskeyUserHandle(ctx context.Context, rpID, userID string) ([]byte, error) {
	handle, err := r.passkeyUserHandle(ctx, rpID, userID)
	if !errors.Is(err, sql.ErrNoRows) {
		return handle, err
	}
	fresh := make([]byte, passkeyUserHandleBytes)
	if _, err := rand.Read(fresh); err != nil {
		return nil, fmt.Errorf("could not generate a passkey user handle: %w", err)
	}
	if _, err := r.writer(ctx).ExecContext(ctx, r.q(`
		INSERT INTO {{schema}}.passkey_users (rp_id, user_id, user_handle) VALUES ($1, $2, $3)
		ON CONFLICT (rp_id, user_id) DO NOTHING`), rpID, userID, fresh); err != nil {
		if isForeignKeyViolation(err) {
			return nil, fmt.Errorf("user not found: %w", model.ErrNotFound)
		}
		return nil, err
	}
	// A concurrent first call may have inserted first; this read sees whichever won.
	return r.passkeyUserHandle(ctx, rpID, userID)
}

func (r *Repository) passkeyUserHandle(ctx context.Context, rpID, userID string) ([]byte, error) {
	var handle []byte
	err := r.writer(ctx).QueryRowContext(ctx, r.q(
		"SELECT user_handle FROM {{schema}}.passkey_users WHERE rp_id=$1 AND user_id=$2"), rpID, userID).Scan(&handle)
	return handle, err
}

// PasskeyUserIDByHandle returns the user whose handle at rpID is handle, or
// model.ErrNotFound.
func (r *Repository) PasskeyUserIDByHandle(ctx context.Context, rpID string, handle []byte) (string, error) {
	var userID string
	err := r.writer(ctx).QueryRowContext(ctx, r.q(
		"SELECT user_id FROM {{schema}}.passkey_users WHERE rp_id=$1 AND user_handle=$2"), rpID, handle).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("no user for this passkey user handle: %w", model.ErrNotFound)
	}
	return userID, err
}

// ListPasskeysFromPrimary returns userID's passkeys at rpID from the primary, oldest
// first, for a WebAuthn ceremony.
func (r *Repository) ListPasskeysFromPrimary(ctx context.Context, rpID, userID string) ([]*model.Passkey, error) {
	return r.listPasskeys(ctx, r.writer(ctx), rpID, userID)
}

// ListPasskeys returns userID's passkeys at rpID from the replica, oldest first.
func (r *Repository) ListPasskeys(ctx context.Context, rpID, userID string) ([]*model.Passkey, error) {
	return r.listPasskeys(ctx, r.reader(ctx), rpID, userID)
}

func (r *Repository) listPasskeys(ctx context.Context, db dbtx, rpID, userID string) ([]*model.Passkey, error) {
	rows, err := db.QueryContext(ctx, r.q("SELECT "+passkeyColumns+
		" FROM {{schema}}.passkeys WHERE rp_id=$1 AND user_id=$2 ORDER BY created_at, credential_id"), rpID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list passkeys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	passkeys := []*model.Passkey{}
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan passkey: %w", err)
		}
		passkeys = append(passkeys, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating passkeys: %w", err)
	}
	return passkeys, nil
}

// InsertPasskey stores a registered passkey; p.CreatedAt is set. It returns
// model.ErrPasskeyAlreadyRegistered when the credential ID is taken at the RP ID,
// and model.ErrNotFound when the user has no handle there (PasskeyUserHandle was
// never called, or the user does not exist).
func (r *Repository) InsertPasskey(ctx context.Context, p *model.Passkey) error {
	transports := p.Transports
	if transports == nil {
		transports = []string{}
	}
	transportsJSON, err := json.Marshal(transports)
	if err != nil {
		return fmt.Errorf("failed to encode passkey transports: %w", err)
	}
	err = r.writer(ctx).QueryRowContext(ctx, r.q(`
		INSERT INTO {{schema}}.passkeys (
			rp_id, credential_id, user_id, name, public_key, sign_count, transports, user_verified,
			backup_eligible, backup_state, aaguid, attestation_type, attestation_format,
			attestation_object, attestation_client_data_json
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11, $12, $13, $14, $15)
		RETURNING created_at`),
		p.RPID, p.CredentialID, p.UserID, p.Name, p.PublicKey, int64(p.SignCount), string(transportsJSON),
		p.UserVerified, p.BackupEligible, p.BackupState, nonNilBytes(p.AAGUID), p.AttestationType,
		p.AttestationFormat, nonNilBytes(p.AttestationObject), nonNilBytes(p.AttestationClientDataJSON),
	).Scan(&p.CreatedAt)
	switch {
	case isUniqueViolation(err):
		return model.ErrPasskeyAlreadyRegistered
	case isForeignKeyViolation(err):
		return fmt.Errorf("no passkey user handle for this user at this RP ID: %w", model.ErrNotFound)
	}
	p.Transports = transports
	return err
}

// nonNilBytes keeps an absent value from being written as NULL to a NOT NULL BYTEA
// column.
func nonNilBytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// RecordPasskeyUse writes a sign-in's state back to one of userID's passkeys: the
// signature counter, the backup state, the uvInitialized flag (only ever set) and the
// time. The counter must go up, unless the passkey has none (it reported 0 and still
// does): otherwise it returns model.ErrPasskeyCloned and changes nothing. The check
// and the write hold the row's lock, so two sign-ins cannot both pass with one count.
// It returns model.ErrNotFound when userID has no such passkey.
func (r *Repository) RecordPasskeyUse(ctx context.Context, req model.PasskeyUseRequest) error {
	tx, err := r.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var stored int64
	err = tx.QueryRowContext(ctx, r.q(`
		SELECT sign_count FROM {{schema}}.passkeys
		WHERE rp_id=$1 AND credential_id=$2 AND user_id=$3 FOR UPDATE`),
		req.RPID, req.CredentialID, req.UserID).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("passkey not found: %w", model.ErrNotFound)
	}
	if err != nil {
		return err
	}
	if count := int64(req.SignCount); count <= stored && (count != 0 || stored != 0) {
		return model.ErrPasskeyCloned
	}
	if _, err := tx.ExecContext(ctx, r.q(`
		UPDATE {{schema}}.passkeys
		SET sign_count=$4, backup_state=$5, user_verified = user_verified OR $6, last_used_at=$7
		WHERE rp_id=$1 AND credential_id=$2 AND user_id=$3`),
		req.RPID, req.CredentialID, req.UserID, int64(req.SignCount), req.BackupState, req.UserVerified, time.Now()); err != nil {
		return err
	}
	return tx.Commit()
}

// RenamePasskey sets the label of one of userID's passkeys; a passkey that does not
// exist, or belongs to another user, is model.ErrNotFound.
func (r *Repository) RenamePasskey(ctx context.Context, rpID, userID string, credentialID []byte, name string) error {
	result, err := r.writer(ctx).ExecContext(ctx, r.q(
		"UPDATE {{schema}}.passkeys SET name=$4 WHERE rp_id=$1 AND credential_id=$2 AND user_id=$3"),
		rpID, credentialID, userID, name)
	if err != nil {
		return fmt.Errorf("failed to rename passkey: %w", err)
	}
	return requireRowsAffected(result, fmt.Errorf("passkey not found: %w", model.ErrNotFound))
}

// DeletePasskey removes one of userID's passkeys; a passkey that does not exist, or
// belongs to another user, is model.ErrNotFound. The user's handle stays, so a
// passkey registered later carries the same one.
func (r *Repository) DeletePasskey(ctx context.Context, rpID, userID string, credentialID []byte) error {
	result, err := r.writer(ctx).ExecContext(ctx, r.q(
		"DELETE FROM {{schema}}.passkeys WHERE rp_id=$1 AND credential_id=$2 AND user_id=$3"),
		rpID, credentialID, userID)
	if err != nil {
		return fmt.Errorf("failed to delete passkey: %w", err)
	}
	return requireRowsAffected(result, fmt.Errorf("passkey not found: %w", model.ErrNotFound))
}
