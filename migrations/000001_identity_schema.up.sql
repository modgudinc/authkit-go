-- Identity schema for authkit-go (consolidated).
--
-- The complete schema in a single migration. All identifiers are UUIDv7 minted
-- by the application (uuid.NewV7()); columns carry no SQL-side UUID default and
-- there is no DB-side UUID generator. Account status-change audit rows
-- (user_status_changes) are written by the library in Go (in the same
-- transaction as the status change), not by a database trigger.
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

CREATE TABLE IF NOT EXISTS authkit.users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL REFERENCES authkit.tenants(tenant_id) ON DELETE CASCADE,
    roles JSONB NOT NULL DEFAULT '[]'::jsonb,
    token_version INTEGER NOT NULL DEFAULT 0,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    disabled_at TIMESTAMPTZ,
    is_locked BOOLEAN NOT NULL DEFAULT false,
    locked_until TIMESTAMPTZ,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    last_failed_login TIMESTAMPTZ,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT users_tenant_email_unique UNIQUE (tenant_id, email)
);

CREATE INDEX IF NOT EXISTS idx_users_email ON authkit.users(email);
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON authkit.users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_is_enabled ON authkit.users(is_enabled);
CREATE INDEX IF NOT EXISTS idx_users_is_locked ON authkit.users(is_locked);
CREATE INDEX IF NOT EXISTS idx_users_locked_until ON authkit.users(locked_until) WHERE locked_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_created_at ON authkit.users(created_at DESC);

DROP TRIGGER IF EXISTS trigger_users_updated_at ON authkit.users;
CREATE TRIGGER trigger_users_updated_at
    BEFORE UPDATE ON authkit.users
    FOR EACH ROW
    EXECUTE FUNCTION authkit.update_updated_at();

CREATE TABLE IF NOT EXISTS authkit.invitations (
    code VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL REFERENCES authkit.tenants(tenant_id) ON DELETE CASCADE,
    created_by UUID NOT NULL REFERENCES authkit.users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    roles JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 1,
    current_uses INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT invitations_current_uses_check CHECK (current_uses <= max_uses),
    CONSTRAINT invitations_expires_after_created_check CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_invitations_tenant_id ON authkit.invitations (tenant_id);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON authkit.invitations (email);
CREATE INDEX IF NOT EXISTS idx_invitations_expires_at ON authkit.invitations (expires_at);
CREATE INDEX IF NOT EXISTS idx_invitations_created_by ON authkit.invitations (created_by);
CREATE INDEX IF NOT EXISTS idx_invitations_created_at ON authkit.invitations (created_at DESC);

-- key_id holds an application-minted UUIDv7. key_hash is UNIQUE, which already
-- provides the index used by the hash lookup in ValidateAPIKey (no separate
-- key_hash index).
CREATE TABLE IF NOT EXISTS authkit.api_keys (
    key_id UUID PRIMARY KEY,
    key_hash VARCHAR(512) NOT NULL UNIQUE,
    tenant_id VARCHAR(255) NOT NULL REFERENCES authkit.tenants(tenant_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    created_by UUID NOT NULL REFERENCES authkit.users(id) ON DELETE CASCADE,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_id ON authkit.api_keys (tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_created_by ON authkit.api_keys (created_by);
CREATE INDEX IF NOT EXISTS idx_api_keys_created_at ON authkit.api_keys (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at ON authkit.api_keys (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS authkit.provider_keys (
    tenant_id VARCHAR(255) NOT NULL REFERENCES authkit.tenants(tenant_id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    encrypted_key TEXT NOT NULL,
    masked_key VARCHAR(100),
    created_by UUID NOT NULL REFERENCES authkit.users(id) ON DELETE CASCADE,
    last_verified_at TIMESTAMPTZ,
    is_valid BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_provider_keys_tenant_id ON authkit.provider_keys (tenant_id);
CREATE INDEX IF NOT EXISTS idx_provider_keys_provider ON authkit.provider_keys (provider);
CREATE INDEX IF NOT EXISTS idx_provider_keys_created_at ON authkit.provider_keys (created_at DESC);

DROP TRIGGER IF EXISTS trigger_provider_keys_updated_at ON authkit.provider_keys;
CREATE TRIGGER trigger_provider_keys_updated_at
    BEFORE UPDATE ON authkit.provider_keys
    FOR EACH ROW
    EXECUTE FUNCTION authkit.update_updated_at();

-- Refresh tokens.
-- family_id groups every token descended from a single login. On rotation the
-- old token is soft-revoked (revoked_at set) rather than deleted so that a later
-- presentation of an already-consumed token can be detected as reuse/theft, at
-- which point the whole family is revoked. Rows are cleaned up after expiry.
CREATE TABLE IF NOT EXISTS authkit.refresh_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES authkit.users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    family_id UUID NOT NULL,
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
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON authkit.refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_id ON authkit.refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON authkit.refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_ip_address ON authkit.refresh_tokens(ip_address);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_last_used_at ON authkit.refresh_tokens(last_used_at DESC);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_device_name ON authkit.refresh_tokens(device_name);

-- One-time verification codes (OTP).
-- Scoped by tenant_id so the same email in different tenants gets independent
-- codes (no cross-tenant overwrite or cross-tenant verification), and keyed by
-- purpose so codes for distinct flows (signup vs reset) do not evict each other.
-- attempts tracks failed validation attempts to enforce lockout against online
-- brute force of the short numeric code.
CREATE TABLE IF NOT EXISTS authkit.verification_codes (
    tenant_id VARCHAR(255) NOT NULL REFERENCES authkit.tenants(tenant_id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    code VARCHAR(10) NOT NULL,
    purpose VARCHAR(50) NOT NULL DEFAULT 'signup',
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, email, purpose)
);

-- (tenant_id, email) lookups are served by the left prefix of the PRIMARY KEY
-- (tenant_id, email, purpose) — no separate (tenant_id, email) index needed.
CREATE INDEX IF NOT EXISTS idx_verification_codes_expires_at ON authkit.verification_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_verification_codes_purpose ON authkit.verification_codes(purpose);

-- Account status-change audit trail. Written by the application in Go (id is a
-- uuid.NewV7()) on every is_enabled/is_locked transition; there is no DB trigger.
CREATE TABLE IF NOT EXISTS authkit.user_status_changes (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES authkit.users(id) ON DELETE CASCADE,
    status_type VARCHAR(50) NOT NULL,
    changed_by UUID REFERENCES authkit.users(id),
    changed_by_type VARCHAR(20) NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason TEXT,
    metadata JSONB
);

CREATE INDEX IF NOT EXISTS idx_user_status_changes_user_id ON authkit.user_status_changes(user_id, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_status_changes_status_type ON authkit.user_status_changes(status_type, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_status_changes_changed_by ON authkit.user_status_changes(changed_by);
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
