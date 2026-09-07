-- Optional: required only by SessionOptional / SessionRequired.
-- For a custom IdentitySchema replace authkit consistently in this migration.
CREATE TABLE authkit.sessions (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL REFERENCES authkit.users(id) ON DELETE CASCADE,
    namespace VARCHAR(255) NOT NULL CHECK (length(namespace) > 0),
    installation_id VARCHAR(255) NOT NULL CHECK (length(installation_id) > 0),
    token_version INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason VARCHAR(255) NOT NULL DEFAULT '',
    CHECK (expires_at <= absolute_expires_at),
    CHECK (created_at < expires_at)
);
CREATE INDEX sessions_installation_idx ON authkit.sessions (namespace, user_id, installation_id);
CREATE INDEX sessions_expiry_idx ON authkit.sessions (expires_at);
