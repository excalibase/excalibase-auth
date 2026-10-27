DROP TABLE IF EXISTS email_change_tokens;
ALTER TABLE users DROP COLUMN app_metadata, DROP COLUMN user_metadata;
