DROP TABLE IF EXISTS auth.email_verification_tokens;
ALTER TABLE auth.users DROP COLUMN IF EXISTS email_verified;
