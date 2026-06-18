-- Reverses 000001_identity_schema.up.sql by dropping the whole identity schema.
--
-- The schema name here MUST match the up migration. Applications that configured a
-- non-default schema and edited the up migration accordingly must replace "authkit"
-- below with the same name; otherwise this rollback either no-ops or drops the wrong
-- schema. (The runtime Go code resolves the schema dynamically; only these two raw
-- SQL files carry the literal name.)
DROP SCHEMA IF EXISTS authkit CASCADE;
