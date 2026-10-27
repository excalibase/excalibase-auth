DROP TABLE IF EXISTS guest_lock;
DROP TABLE IF EXISTS guest_sign_ups;
ALTER TABLE users DROP KEY idx_users_guests, DROP COLUMN is_guest;
