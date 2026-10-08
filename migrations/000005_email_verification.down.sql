-- Reverses 000005_email_verification.up.sql. Roll back the code that reads the
-- column first. Verification records are lost: users start unverified again if the
-- migration is reapplied.
ALTER TABLE authkit.users DROP COLUMN IF EXISTS email_verified_at;
