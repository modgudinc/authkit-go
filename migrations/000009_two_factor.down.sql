-- Reverses 000009_two_factor.up.sql. Unset Config.TwoFactorConfig first: with it
-- set, password logins fail without these tables. Users keep their accounts and
-- passwords; their authenticator-app factors, recovery codes and pending two-factor
-- logins are dropped, so two-factor is off for everyone.
DROP TABLE IF EXISTS authkit.second_factor_challenges;
DROP TABLE IF EXISTS authkit.recovery_codes;
DROP TABLE IF EXISTS authkit.totp_factors;
