DROP TABLE IF EXISTS auth_codes;
DROP TABLE IF EXISTS flow_states;
DROP TABLE IF EXISTS identities;
UPDATE users SET password = '!no-password' WHERE password IS NULL;
ALTER TABLE users MODIFY password VARCHAR(255) NOT NULL, MODIFY email VARCHAR(100) NOT NULL;
