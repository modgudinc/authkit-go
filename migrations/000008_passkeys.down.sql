-- Reverses 000008_passkeys.up.sql. Users keep their accounts; their passkeys and
-- WebAuthn user handles are dropped, so every passkey stops working.
DROP TABLE IF EXISTS authkit.passkeys;
DROP TABLE IF EXISTS authkit.passkey_users;
