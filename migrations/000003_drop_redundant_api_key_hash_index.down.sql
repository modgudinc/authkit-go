-- Copyright 2026 Modgud, Inc.
-- SPDX-License-Identifier: Apache-2.0
--
-- Reverts 000003: recreate the (redundant) plain index on api_keys.key_hash.

CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON authkit.api_keys (key_hash);
