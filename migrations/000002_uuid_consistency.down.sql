-- Copyright 2026 Modgud, Inc.
-- SPDX-License-Identifier: Apache-2.0
--
-- Reverts 000002: restore gen_random_uuid() (v4) id defaults, drop the v7
-- generator, and type key_id back to VARCHAR(255).

ALTER TABLE authkit.users               ALTER COLUMN id        SET DEFAULT gen_random_uuid();
ALTER TABLE authkit.refresh_tokens      ALTER COLUMN id        SET DEFAULT gen_random_uuid();
ALTER TABLE authkit.refresh_tokens      ALTER COLUMN family_id SET DEFAULT gen_random_uuid();
ALTER TABLE authkit.user_status_changes ALTER COLUMN id        SET DEFAULT gen_random_uuid();
ALTER TABLE authkit.auth_events         ALTER COLUMN id        SET DEFAULT gen_random_uuid();

DROP FUNCTION IF EXISTS authkit.uuid_generate_v7();

ALTER TABLE authkit.api_keys
    ALTER COLUMN key_id TYPE VARCHAR(255) USING key_id::text;
