-- Reverses 000010_sessions_grants.up.sql: the roles lose their access to
-- authkit.sessions again. Without the roles it does nothing.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authkit_rw') THEN
        REVOKE SELECT, INSERT, UPDATE, DELETE ON authkit.sessions FROM authkit_rw;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authkit_ro') THEN
        REVOKE SELECT ON authkit.sessions FROM authkit_ro;
    END IF;
END;
$$;
