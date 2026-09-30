-- EXC-370: an account may switch between several roles, and every change of
-- an account's roles is recorded with who made it.

-- A role name is up to 63 characters (a Postgres identifier).
ALTER TABLE auth.users ALTER COLUMN role TYPE VARCHAR(63);

-- NULL means the account may act only as users.role.
ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS allowed_roles TEXT[];

CREATE TABLE IF NOT EXISTS auth.role_changes (
    id                BIGSERIAL PRIMARY KEY,
    user_id           BIGINT NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    old_role          TEXT NOT NULL,
    new_role          TEXT NOT NULL,
    old_allowed_roles TEXT[] NOT NULL,
    new_allowed_roles TEXT[] NOT NULL,
    actor             TEXT NOT NULL,              -- studio:<platform user id> | service-key:<api key id>
    changed_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_role_changes_user_id ON auth.role_changes(user_id);
