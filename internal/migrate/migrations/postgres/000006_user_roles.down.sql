DROP TABLE IF EXISTS auth.role_changes;
ALTER TABLE auth.users DROP COLUMN IF EXISTS allowed_roles;
-- users.role stays VARCHAR(63): narrowing it could fail on names already stored.
