-- Reverses 000006_refresh_token_replacement.up.sql. Unset
-- JWTConfig.RefreshGracePeriod and deploy that first: code with a grace period
-- reads and writes the column.
ALTER TABLE authkit.refresh_tokens DROP COLUMN IF EXISTS replaced_by;
