-- Optional: required only by PasskeyService. It depends on 000001 alone, so it
-- works with every session mode. It only adds tables, so it is safe while older
-- code runs.
-- For a custom IdentitySchema replace authkit consistently in this migration.

-- A user's WebAuthn user handle at one relying party (rp_id, the WebAuthn RP ID):
-- the opaque bytes an authenticator keeps with a passkey and returns at a
-- discoverable sign-in. The library makes it random, never the user id or email,
-- and it stays the same for every passkey the user registers at that RP ID.
-- Deleting the user deletes it, and with it the user's passkeys.
CREATE TABLE IF NOT EXISTS authkit.passkey_users (
    rp_id VARCHAR(253) NOT NULL CHECK (length(rp_id) > 0),
    user_id VARCHAR(36) NOT NULL REFERENCES authkit.users(id) ON DELETE CASCADE,
    user_handle BYTEA NOT NULL CHECK (octet_length(user_handle) BETWEEN 1 AND 64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (rp_id, user_id),
    UNIQUE (rp_id, user_handle)
);

-- user_id serves the user FK cascade.
CREATE INDEX IF NOT EXISTS idx_passkey_users_user ON authkit.passkey_users (user_id);

-- One WebAuthn credential (a passkey or a security key) the application verified
-- in a registration ceremony, holding the WebAuthn credential record: the public
-- key, the signature counter, the transports, and the uvInitialized (user_verified),
-- backup eligible and backup state flags, plus the authenticator's AAGUID and the
-- attestation, which the application may keep to check against authenticator
-- metadata later. A credential belongs to the user handle row of its user at its RP
-- ID, so it is deleted with the user. name is the label the person chose.
-- sign_count, user_verified, backup_state and last_used_at change at each sign-in
-- (PasskeyService.RecordUse); nothing else changes but name.
CREATE TABLE IF NOT EXISTS authkit.passkeys (
    rp_id VARCHAR(253) NOT NULL,
    credential_id BYTEA NOT NULL CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
    user_id VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL DEFAULT '',
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) > 0),
    sign_count BIGINT NOT NULL DEFAULT 0 CHECK (sign_count BETWEEN 0 AND 4294967295),
    transports JSONB NOT NULL DEFAULT '[]'::jsonb,
    user_verified BOOLEAN NOT NULL DEFAULT false,
    backup_eligible BOOLEAN NOT NULL DEFAULT false,
    backup_state BOOLEAN NOT NULL DEFAULT false,
    aaguid BYTEA NOT NULL DEFAULT ''::bytea CHECK (octet_length(aaguid) IN (0, 16)),
    attestation_type VARCHAR(64) NOT NULL DEFAULT '',
    attestation_format VARCHAR(64) NOT NULL DEFAULT '',
    attestation_object BYTEA NOT NULL DEFAULT ''::bytea,
    attestation_client_data_json BYTEA NOT NULL DEFAULT ''::bytea,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    PRIMARY KEY (rp_id, credential_id),
    FOREIGN KEY (rp_id, user_id) REFERENCES authkit.passkey_users (rp_id, user_id) ON DELETE CASCADE,
    -- A credential that cannot be backed up is never backed up.
    CHECK (backup_eligible OR NOT backup_state)
);

-- (rp_id, user_id, created_at) serves "a user's passkeys" and the FK cascade.
CREATE INDEX IF NOT EXISTS idx_passkeys_user ON authkit.passkeys (rp_id, user_id, created_at);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authkit_rw') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON authkit.passkey_users, authkit.passkeys TO authkit_rw;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authkit_ro') THEN
        GRANT SELECT ON authkit.passkey_users, authkit.passkeys TO authkit_ro;
    END IF;
END;
$$;
