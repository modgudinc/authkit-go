-- Needed only to set JWTConfig.RefreshGracePeriod: apply it before deploying code
-- that sets the period. It only adds a nullable column, so it is safe while older
-- code runs, and code without a grace period never reads or writes it.

-- The refresh token issued when this one was consumed. With a grace period, a
-- consumed token whose replacement has never been used can be exchanged again (the
-- client lost the response that carried the replacement); the unused replacement is
-- revoked and this column moves to the new one. NULL for tokens consumed without a
-- grace period, revoked by a logout, or not yet consumed.
ALTER TABLE authkit.refresh_tokens ADD COLUMN IF NOT EXISTS replaced_by VARCHAR(36);
