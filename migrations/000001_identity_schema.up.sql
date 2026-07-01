-- Identity schema for authkit-go (consolidated) — decoupled-identity model.
--
-- The complete schema in a single migration. All identifiers are UUIDv7 strings
-- minted by the application (uuid.NewV7().String()) and stored as VARCHAR(36);
-- columns carry no SQL-side UUID type or default and there is no DB-side UUID
-- generator. Account status-change audit rows (user_status_changes) are written
-- by the library in Go (in the same transaction as the status change), not by a
-- database trigger.
--
-- Identity is DECOUPLED from tenancy:
--   * users is a GLOBAL identity (email globally unique); it carries no tenant_id
--     and no roles.
--   * memberships is the user<->tenant graph: which identity belongs to which
--     tenant, with roles (OPAQUE strings the embedding app interprets) and a
--     per-membership token_version for role/revoke invalidation.
--   * users.token_version invalidates ALL of an identity's access tokens
--     (credential events); memberships.token_version invalidates only that
--     workspace's tokens (role events).
--   * verification_codes (OTP) are keyed by (email, purpose) globally.
--
-- Applications that configure a non-default schema should copy this migration
-- and replace "authkit" with the configured schema name.

CREATE SCHEMA IF NOT EXISTS authkit;

CREATE TABLE IF NOT EXISTS authkit.tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    allowed_domains TEXT[] NOT NULL,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- cardinality() returns 0 (not NULL) for an empty array, so this actually
    -- rejects '{}'. array_length(arr, 1) returns NULL for an empty array, and a
    -- CHECK only fails on an explicit FALSE — so NULL > 0 would let '{}' through.
    CONSTRAINT check_allowed_domains_not_empty CHECK (cardinality(allowed_domains) > 0)
);

CREATE INDEX IF NOT EXISTS idx_tenants_allowed_domains ON authkit.tenants USING GIN (allowed_domains);
CREATE INDEX IF NOT EXISTS idx_tenants_created_at ON authkit.tenants (created_at DESC);

CREATE OR REPLACE FUNCTION authkit.update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_tenants_updated_at ON authkit.tenants;
CREATE TRIGGER trigger_tenants_updated_at
    BEFORE UPDATE ON authkit.tenants
    FOR EACH ROW
    EXECUTE FUNCTION authkit.update_updated_at();

-- Users — the GLOBAL identity. No tenant_id, no roles (those live on memberships).
-- email is globally unique (one identity per email). token_version invalidates all
-- of this identity's access tokens (credential events: password change, disable,
-- logout-all). Account status (enable/disable, lock/unlock, failed-login lockout)
-- is identity-level.
CREATE TABLE IF NOT EXISTS authkit.users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    token_version INTEGER NOT NULL DEFAULT 0,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    disabled_at TIMESTAMPTZ,
    is_locked BOOLEAN NOT NULL DEFAULT false,
    locked_until TIMESTAMPTZ,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    last_failed_login TIMESTAMPTZ,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Global, case-insensitive email uniqueness: one identity per email across all
-- tenants. Exact lookups by lower(email) use this index; List orders by created_at.
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_unique ON authkit.users(lower(email));
CREATE INDEX IF NOT EXISTS idx_users_created_at ON authkit.users(created_at DESC);

DROP TRIGGER IF EXISTS trigger_users_updated_at ON authkit.users;
CREATE TRIGGER trigger_users_updated_at
    BEFORE UPDATE ON authkit.users
    FOR EACH ROW
    EXECUTE FUNCTION authkit.update_updated_at();

-- Memberships — the user<->tenant graph. roles are OPAQUE strings the embedding
-- application interprets (authkit owns the graph, the app owns the policy).
-- token_version invalidates only this workspace's access tokens (role change /
-- membership revoke), independently of the identity-level users.token_version.
CREATE TABLE IF NOT EXISTS authkit.memberships (
    user_id VARCHAR(36) NOT NULL REFERENCES authkit.users(id) ON DELETE CASCADE,
    tenant_id VARCHAR(255) NOT NULL REFERENCES authkit.tenants(tenant_id) ON DELETE CASCADE,
    roles JSONB NOT NULL DEFAULT '[]'::jsonb,
    token_version INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, tenant_id),
    CONSTRAINT memberships_status_check CHECK (status IN ('active', 'suspended'))
);

-- (user_id) — the PK prefix — serves "a user's workspaces" and the user FK cascade.
-- (tenant_id) serves "a tenant's members" and the tenant FK cascade.
CREATE INDEX IF NOT EXISTS idx_memberships_tenant ON authkit.memberships (tenant_id, created_at DESC);

DROP TRIGGER IF EXISTS trigger_memberships_updated_at ON authkit.memberships;
CREATE TRIGGER trigger_memberships_updated_at
    BEFORE UPDATE ON authkit.memberships
    FOR EACH ROW
    EXECUTE FUNCTION authkit.update_updated_at();

CREATE TABLE IF NOT EXISTS authkit.invitations (
    code VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL REFERENCES authkit.tenants(tenant_id) ON DELETE CASCADE,
    created_by VARCHAR(36) NOT NULL REFERENCES authkit.users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    roles JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 1,
    current_uses INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT invitations_current_uses_check CHECK (current_uses <= max_uses),
    CONSTRAINT invitations_expires_after_created_check CHECK (expires_at > created_at)
);

-- Composite (tenant_id, created_at DESC) serves the tenant-scoped list endpoints
-- (and its tenant_id prefix the tenant FK cascade), replacing the separate
-- (tenant_id) and (created_at) indexes.
CREATE INDEX IF NOT EXISTS idx_invitations_tenant_created ON authkit.invitations (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON authkit.invitations (email);
CREATE INDEX IF NOT EXISTS idx_invitations_expires_at ON authkit.invitations (expires_at);
CREATE INDEX IF NOT EXISTS idx_invitations_created_by ON authkit.invitations (created_by);

-- key_id holds an application-minted UUIDv7. key_hash is UNIQUE, which already
-- provides the index used by the hash lookup in ValidateAPIKey (no separate
-- key_hash index). API keys remain tenant-scoped (a machine credential acts within
-- one tenant); created_by is now a GLOBAL user id.
CREATE TABLE IF NOT EXISTS authkit.api_keys (
    key_id VARCHAR(36) PRIMARY KEY,
    key_hash VARCHAR(512) NOT NULL UNIQUE,
    tenant_id VARCHAR(255) NOT NULL REFERENCES authkit.tenants(tenant_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    created_by VARCHAR(36) NOT NULL REFERENCES authkit.users(id) ON DELETE CASCADE,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Composite (tenant_id, created_at DESC) serves ListAPIKeys and CountAPIKeysByTenant
-- (and the tenant FK cascade via its prefix), replacing separate (tenant_id) + (created_at).
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_created ON authkit.api_keys (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_keys_created_by ON authkit.api_keys (created_by);
CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at ON authkit.api_keys (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS authkit.provider_keys (
    tenant_id VARCHAR(255) NOT NULL REFERENCES authkit.tenants(tenant_id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    encrypted_key TEXT NOT NULL,
    masked_key VARCHAR(100),
    created_by VARCHAR(36) NOT NULL REFERENCES authkit.users(id) ON DELETE CASCADE,
    last_verified_at TIMESTAMPTZ,
    is_valid BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, provider)
);

-- (tenant_id) and (tenant_id, provider) lookups — including ListSecrets'
-- "WHERE tenant_id ORDER BY provider" — are served by the PRIMARY KEY
-- (tenant_id, provider), so no separate tenant_id/provider index is needed.
CREATE INDEX IF NOT EXISTS idx_provider_keys_created_at ON authkit.provider_keys (created_at DESC);

DROP TRIGGER IF EXISTS trigger_provider_keys_updated_at ON authkit.provider_keys;
CREATE TRIGGER trigger_provider_keys_updated_at
    BEFORE UPDATE ON authkit.provider_keys
    FOR EACH ROW
    EXECUTE FUNCTION authkit.update_updated_at();

-- Refresh tokens — the IDENTITY session (user-scoped, no tenant). One login = one
-- family; the workspace-scoped access tokens minted from it carry the active
-- membership's tenant + roles. On rotation the old token is soft-revoked
-- (revoked_at set) rather than deleted so a later presentation of an
-- already-consumed token is detected as reuse/theft, at which point the whole
-- family is revoked. Rows are cleaned up after expiry.
CREATE TABLE IF NOT EXISTS authkit.refresh_tokens (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL REFERENCES authkit.users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    family_id VARCHAR(36) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    device_name VARCHAR(255),
    last_used_at TIMESTAMPTZ DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- token_hash is declared UNIQUE (above), which already creates the index used by
-- the hot GetByTokenHash / RotateRefreshToken lookups — no separate token_hash index.
-- user_id (logout-all / list), family_id (reuse-family revoke), and expires_at
-- (cleanup) are the indexed access paths; token_hash uses its UNIQUE index. The
-- ip_address/last_used_at/device_name columns are session metadata, never filtered
-- on, so they are not indexed.
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON authkit.refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_id ON authkit.refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON authkit.refresh_tokens(expires_at);

-- One-time verification codes (OTP). Keyed by (email, purpose) GLOBALLY — email is
-- a global identity now, so an OTP for signup/reset is identity-level, not
-- tenant-scoped. purpose keeps codes for distinct flows (signup vs reset) from
-- evicting each other. attempts enforces lockout against online brute force of the
-- short numeric code. code_hash stores a keyed HMAC-SHA256 of the OTP (64 hex
-- chars), never the plaintext, so a read-only DB/backup/replica disclosure does not
-- expose usable codes (the validating server holds the HMAC secret).
CREATE TABLE IF NOT EXISTS authkit.verification_codes (
    email VARCHAR(255) NOT NULL,
    code_hash VARCHAR(64) NOT NULL,
    purpose VARCHAR(50) NOT NULL DEFAULT 'signup',
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (email, purpose)
);

-- (email) lookups are served by the left prefix of the PRIMARY KEY (email, purpose).
-- expires_at drives DeleteExpired. purpose is never filtered on alone.
CREATE INDEX IF NOT EXISTS idx_verification_codes_expires_at ON authkit.verification_codes(expires_at);

-- Account status-change audit trail. Written by the application in Go (id is a
-- uuid.NewV7()) on every is_enabled/is_locked transition; there is no DB trigger.
-- The table has no expiry column and grows for the life of the deployment; prune
-- it per a retention policy via UserService.CleanupStatusChanges. Read it via
-- UserService.StatusHistory. The user_id FK is ON DELETE CASCADE intentionally:
-- an audit row is meaningful only alongside the user it describes, and the library
-- soft-deletes users (sets is_enabled=false) rather than removing the row, so the
-- trail is retained for the account's lifetime. An operator who hard-deletes a
-- user should archive these rows first if they are needed for compliance.
-- changed_by/reason are reserved for callers that extend the trail (the library
-- leaves them NULL and conveys provenance via changed_by_type), so there is no
-- index on changed_by.
CREATE TABLE IF NOT EXISTS authkit.user_status_changes (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL REFERENCES authkit.users(id) ON DELETE CASCADE,
    status_type VARCHAR(50) NOT NULL,
    changed_by VARCHAR(36) REFERENCES authkit.users(id),
    changed_by_type VARCHAR(20) NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason TEXT,
    metadata JSONB
);

CREATE INDEX IF NOT EXISTS idx_user_status_changes_user_id ON authkit.user_status_changes(user_id, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_status_changes_status_type ON authkit.user_status_changes(status_type, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_status_changes_changed_at ON authkit.user_status_changes(changed_at DESC);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authkit_rw') THEN
        GRANT USAGE ON SCHEMA authkit TO authkit_rw;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA authkit TO authkit_rw;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA authkit TO authkit_rw;
        GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authkit TO authkit_rw;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authkit_ro') THEN
        GRANT USAGE ON SCHEMA authkit TO authkit_ro;
        GRANT SELECT ON ALL TABLES IN SCHEMA authkit TO authkit_ro;
        GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authkit TO authkit_ro;
    END IF;
END;
$$;
