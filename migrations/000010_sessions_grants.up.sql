-- Grants on authkit.sessions for the optional authkit_rw and authkit_ro roles.
-- 000001 grants on every table that exists when it runs and each later migration
-- grants on the tables it adds, but 000002 added sessions without a grant block, so
-- a deployment that connects as those roles could not read or write sessions. Safe
-- to apply at any time; without the roles it does nothing.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authkit_rw') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON authkit.sessions TO authkit_rw;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authkit_ro') THEN
        GRANT SELECT ON authkit.sessions TO authkit_ro;
    END IF;
END;
$$;
