DROP INDEX IF EXISTS auth.idx_email_change_tokens_guest;
ALTER TABLE auth.email_change_tokens DROP COLUMN IF EXISTS guest_client;
DROP TABLE IF EXISTS auth.guest_lock;
DROP TABLE IF EXISTS auth.guest_sign_ups;
DROP INDEX IF EXISTS auth.idx_users_guests;
ALTER TABLE auth.users DROP COLUMN IF EXISTS is_guest;
