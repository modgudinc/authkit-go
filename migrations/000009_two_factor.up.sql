-- Needed only to set Config.TwoFactorConfig: apply it before deploying code that
-- sets it, because with it set every password login reads totp_factors. It only
-- adds tables, so it is safe while older code runs, and code without two-factor
-- never touches them.
-- For a custom IdentitySchema replace authkit consistently in this migration.

-- A user's authenticator-app (TOTP) factor. secret_ciphertext is the shared secret
-- encrypted with TwoFactorConfig.EncryptionKey (AES-256-GCM, bound to the user id).
-- confirmed_at is NULL while the person is still setting the app up; the factor
-- counts only once they have entered a code from it. last_used_step is the last
-- 30-second step a code was accepted for, so a code is never accepted twice.
-- Deleting the user deletes it.
CREATE TABLE IF NOT EXISTS authkit.totp_factors (
    user_id VARCHAR(36) PRIMARY KEY REFERENCES authkit.users(id) ON DELETE CASCADE,
    secret_ciphertext TEXT NOT NULL CHECK (length(secret_ciphertext) > 0),
    confirmed_at TIMESTAMPTZ,
    last_used_step BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Single-use recovery codes for a user whose factor is on, stored as keyed
-- HMAC-SHA256 hashes (hex). used_at is set when one is spent.
CREATE TABLE IF NOT EXISTS authkit.recovery_codes (
    user_id VARCHAR(36) NOT NULL REFERENCES authkit.users(id) ON DELETE CASCADE,
    code_hash CHAR(64) NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, code_hash)
);

-- A password login waiting for its second factor. token_hash is the SHA-256 (hex)
-- of the challenge returned to the client; login is the request to finish (which
-- call, workspace, installation and session info). A row is deleted when the login
-- finishes, and is useless after expires_at; TwoFactorService.CleanupExpired removes
-- those.
CREATE TABLE IF NOT EXISTS authkit.second_factor_challenges (
    token_hash CHAR(64) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL REFERENCES authkit.users(id) ON DELETE CASCADE,
    login JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- user_id serves the user FK cascade and turning the factor off; expires_at serves
-- CleanupExpired.
CREATE INDEX IF NOT EXISTS idx_second_factor_challenges_user ON authkit.second_factor_challenges (user_id);
CREATE INDEX IF NOT EXISTS idx_second_factor_challenges_expires ON authkit.second_factor_challenges (expires_at);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authkit_rw') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON authkit.totp_factors, authkit.recovery_codes, authkit.second_factor_challenges TO authkit_rw;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authkit_ro') THEN
        GRANT SELECT ON authkit.totp_factors, authkit.recovery_codes, authkit.second_factor_challenges TO authkit_ro;
    END IF;
END;
$$;
