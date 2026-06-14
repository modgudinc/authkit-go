-- Copyright 2026 Modgud, Inc.
-- SPDX-License-Identifier: Apache-2.0
--
-- api_keys.key_hash is declared UNIQUE, which already creates a unique B-tree
-- index used by the hash lookup in ValidateAPIKey. idx_api_keys_key_hash is a
-- second, plain index on the same column — pure redundancy (extra write
-- amplification and disk for no query benefit). Drop it; the UNIQUE index
-- (api_keys_key_hash_key) remains and serves every key_hash lookup.

DROP INDEX IF EXISTS authkit.idx_api_keys_key_hash;
