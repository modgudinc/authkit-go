-- Optional: for applications that applied 000002 (SessionOptional / SessionRequired).
-- Apply it before deploying the release that adds VerifiedLoginService: that code
-- reads sign_in_method on every session lookup. It is safe to apply while older
-- code is still running, which never writes the column (the default records its
-- password logins correctly) and always sends an installation.
-- For a custom IdentitySchema replace authkit consistently in this migration.

-- How each login signed in: 'password' for logins in which authkit checked the
-- password, otherwise the method the application passed to OpenSession.
ALTER TABLE authkit.sessions
    ADD COLUMN IF NOT EXISTS sign_in_method VARCHAR(64) NOT NULL DEFAULT 'password';
ALTER TABLE authkit.sessions DROP CONSTRAINT IF EXISTS sessions_sign_in_method_check;
ALTER TABLE authkit.sessions
    ADD CONSTRAINT sessions_sign_in_method_check CHECK (length(sign_in_method) > 0);

-- OpenSession may open a session without an installation (a browser, for example);
-- its installation_id is ''. RevokeInstallation never matches ''.
ALTER TABLE authkit.sessions DROP CONSTRAINT IF EXISTS sessions_installation_id_check;
