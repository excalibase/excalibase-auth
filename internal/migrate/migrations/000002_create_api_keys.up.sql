-- Schema-qualify all names so the migration is safe under transaction-pooled
-- connections (PgBouncer transaction mode) where session-level SET search_path
-- can be lost mid-migration.

CREATE TABLE IF NOT EXISTS auth.api_keys (
    id           BIGSERIAL PRIMARY KEY,
    key_hash     VARCHAR(64) NOT NULL UNIQUE,           -- SHA-256 hex (64 chars)
    key_prefix   VARCHAR(24) NOT NULL,                  -- first 12 chars of random portion, for display
    key_type     VARCHAR(16) NOT NULL CHECK (key_type IN ('publishable','secret')),
    name         VARCHAR(100),
    created_by   BIGINT REFERENCES auth.users(id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    revoked_by   BIGINT REFERENCES auth.users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON auth.api_keys(key_prefix) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_api_keys_created_by ON auth.api_keys(created_by);
