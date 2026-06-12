-- Copyright 2026 Modgud, Inc.
-- SPDX-License-Identifier: Apache-2.0
--
-- Forward migration on top of 000001. Two consistency fixes:
--
--   1. api_keys.key_id holds an application-generated UUIDv7 but was typed
--      VARCHAR(255). Type it as UUID to match every other id column (users.id,
--      refresh_tokens.id, ...). The application inserts a canonical UUID string,
--      so existing rows cast cleanly.
--
--   2. Id columns defaulted to gen_random_uuid() (UUIDv4) while the application
--      mints UUIDv7. Rows the application does not insert directly — DB defaults
--      and the trigger-populated user_status_changes / auth_events tables — were
--      therefore getting time-unordered v4 ids, defeating the index locality the
--      v7 strategy was chosen for. Switch the DB-side defaults to a UUIDv7
--      generator so every id is time-ordered regardless of who inserts it.

-- 1. key_id: VARCHAR(255) -> UUID
ALTER TABLE authkit.api_keys
    ALTER COLUMN key_id TYPE UUID USING key_id::uuid;

-- 2. UUIDv7 generator (RFC 9562): 48-bit Unix-ms timestamp in the high bits,
-- version (7) and RFC 4122 variant bits set, the remainder random. Depends on
-- pgcrypto (gen_random_bytes), which 000001 already enables.
CREATE OR REPLACE FUNCTION authkit.uuid_generate_v7()
RETURNS uuid
AS $$
DECLARE
    v_bytes bytea;
BEGIN
    -- 16 random bytes ...
    v_bytes = gen_random_bytes(16);
    -- ... with the first 48 bits overwritten by the current Unix time in ms
    -- (int8send is 8 big-endian bytes; the ms value fits in the low 6).
    v_bytes = overlay(
        v_bytes
        PLACING substring(int8send((extract(epoch FROM clock_timestamp()) * 1000)::bigint) FROM 3)
        FROM 1 FOR 6
    );
    -- version 7: high nibble of byte 6 = 0111
    v_bytes = set_byte(v_bytes, 6, (get_byte(v_bytes, 6) & 15) | 112);
    -- RFC 4122 variant: top two bits of byte 8 = 10
    v_bytes = set_byte(v_bytes, 8, (get_byte(v_bytes, 8) & 63) | 128);
    RETURN encode(v_bytes, 'hex')::uuid;
END;
$$ LANGUAGE plpgsql VOLATILE;

ALTER TABLE authkit.users               ALTER COLUMN id        SET DEFAULT authkit.uuid_generate_v7();
ALTER TABLE authkit.refresh_tokens      ALTER COLUMN id        SET DEFAULT authkit.uuid_generate_v7();
ALTER TABLE authkit.refresh_tokens      ALTER COLUMN family_id SET DEFAULT authkit.uuid_generate_v7();
ALTER TABLE authkit.user_status_changes ALTER COLUMN id        SET DEFAULT authkit.uuid_generate_v7();
ALTER TABLE authkit.auth_events         ALTER COLUMN id        SET DEFAULT authkit.uuid_generate_v7();
