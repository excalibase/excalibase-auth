DROP TABLE IF EXISTS auth.email_change_tokens;
ALTER TABLE auth.users DROP COLUMN IF EXISTS app_metadata, DROP COLUMN IF EXISTS user_metadata;
