-- Optional: required only by ExternalIdentityService. It depends on 000001 alone,
-- so it works with every session mode.
-- For a custom IdentitySchema replace authkit consistently in this migration.

-- One row links one account at an outside sign-in provider to one authkit user.
-- (provider, subject) is the provider's stable user id (the OIDC "sub" claim,
-- GitHub's numeric id) and is how a returning sign-in is found; the email is only
-- what the provider last reported, kept for display and audit. A user may link
-- several providers. Deleting the user deletes its links.
CREATE TABLE IF NOT EXISTS authkit.external_identities (
    provider VARCHAR(64) NOT NULL CHECK (length(provider) > 0),
    subject VARCHAR(255) NOT NULL CHECK (length(subject) > 0),
    user_id VARCHAR(36) NOT NULL REFERENCES authkit.users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL DEFAULT '',
    email_verified BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_sign_in_at TIMESTAMPTZ,
    PRIMARY KEY (provider, subject)
);

-- (user_id, provider) serves "a user's linked accounts", the "already linked at this
-- provider" check in Resolve, and the user FK cascade.
CREATE INDEX IF NOT EXISTS idx_external_identities_user ON authkit.external_identities (user_id, provider);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authkit_rw') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON authkit.external_identities TO authkit_rw;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authkit_ro') THEN
        GRANT SELECT ON authkit.external_identities TO authkit_ro;
    END IF;
END;
$$;
