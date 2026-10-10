-- Needed only to set Config.RecordSignIns: apply it before deploying code that sets
-- it. It only adds a table, so it is safe while older code runs, and code that does
-- not record sign-ins never writes to it.

-- One row per sign-in attempt on an existing account: a password login (method
-- 'password') or a VerifiedLoginService.OpenSession (the application's method),
-- successful or refused. Attempts on unknown emails have no account to attach to and
-- are not recorded. failure_reason is '' for a success, else bad_password,
-- no_password, account_disabled, account_locked or no_membership. tenant_id is the
-- workspace the sign-in asked for or selected ('' for none); session_id is the
-- session record it opened ('' when it opened none); namespace is the
-- signing-in application's SessionConfig.Namespace. Rows are written by the library
-- and never updated. Deleting the user deletes its rows; deleting a workspace or a
-- session does not. SignInHistoryService.Cleanup removes old rows.
CREATE TABLE IF NOT EXISTS authkit.sign_in_events (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL REFERENCES authkit.users(id) ON DELETE CASCADE,
    occurred_at TIMESTAMPTZ NOT NULL,
    method VARCHAR(64) NOT NULL CHECK (length(method) > 0),
    succeeded BOOLEAN NOT NULL,
    failure_reason VARCHAR(64) NOT NULL DEFAULT '',
    namespace VARCHAR(255) NOT NULL DEFAULT '',
    tenant_id VARCHAR(255) NOT NULL DEFAULT '',
    session_id VARCHAR(36) NOT NULL DEFAULT '',
    installation_id VARCHAR(255) NOT NULL DEFAULT '',
    ip_address INET,
    user_agent TEXT,
    device_name VARCHAR(255),
    CHECK (succeeded = (failure_reason = ''))
);

-- (user_id, occurred_at, id) serves a user's history, newest first, and the user FK
-- cascade; occurred_at serves Cleanup.
CREATE INDEX IF NOT EXISTS idx_sign_in_events_user ON authkit.sign_in_events (user_id, occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_sign_in_events_occurred_at ON authkit.sign_in_events (occurred_at);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authkit_rw') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON authkit.sign_in_events TO authkit_rw;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authkit_ro') THEN
        GRANT SELECT ON authkit.sign_in_events TO authkit_ro;
    END IF;
END;
$$;
