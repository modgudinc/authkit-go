-- Required for every deployment from the release that adds email verification:
-- user queries read users.email_verified_at. Apply it before deploying that
-- release. It only adds a nullable column, so it is safe while older code runs.
-- For a custom IdentitySchema replace authkit consistently in this migration.

-- When the user's current email address was proven to belong to them: by a code or
-- link the application sent to it (UserService.MarkEmailVerified), or by a
-- provider that verified it when ExternalIdentityService.Resolve created the user.
-- NULL means not known to be verified. Existing users start NULL.
ALTER TABLE authkit.users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;
