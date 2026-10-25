DROP TABLE IF EXISTS auth.auth_codes;
DROP TABLE IF EXISTS auth.flow_states;
DROP TABLE IF EXISTS auth.identities;
-- A provider-only account gets a hash no password matches, so it stays unusable
-- until reset instead of blocking the rollback.
UPDATE auth.users SET password = '!no-password' WHERE password IS NULL;
ALTER TABLE auth.users ALTER COLUMN password SET NOT NULL;
ALTER TABLE auth.users ALTER COLUMN email SET NOT NULL;
