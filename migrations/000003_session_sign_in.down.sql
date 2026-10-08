-- Reverses 000003_session_sign_in.up.sql. Sessions opened without an installation
-- cannot satisfy the restored constraint, so they and their refresh tokens are
-- deleted first; their credentials then fail closed as revoked.
-- Roll back the code that uses VerifiedLoginService before applying this.
DELETE FROM authkit.refresh_tokens
WHERE family_id IN (SELECT id FROM authkit.sessions WHERE installation_id = '');
DELETE FROM authkit.sessions WHERE installation_id = '';
ALTER TABLE authkit.sessions DROP CONSTRAINT IF EXISTS sessions_installation_id_check;
ALTER TABLE authkit.sessions
    ADD CONSTRAINT sessions_installation_id_check CHECK (length(installation_id) > 0);
ALTER TABLE authkit.sessions DROP CONSTRAINT IF EXISTS sessions_sign_in_method_check;
ALTER TABLE authkit.sessions DROP COLUMN IF EXISTS sign_in_method;
