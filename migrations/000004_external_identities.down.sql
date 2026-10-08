-- Reverses 000004_external_identities.up.sql. Users keep their accounts; only the
-- links to outside sign-in providers are dropped.
DROP TABLE IF EXISTS authkit.external_identities;
