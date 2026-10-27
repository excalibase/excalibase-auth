-- EXC-662: end users read and change their own account. Metadata stays out of
-- the token; user_metadata is the user's to write, app_metadata only the
-- project's (secret key or Studio). NULL reads as {}.
ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS user_metadata JSONB,
    ADD COLUMN IF NOT EXISTS app_metadata  JSONB;

-- A requested change of address, proven by a link mailed to the new one. The
-- link is kept as its SHA-256; rows stay a day so the budgets count from them.
CREATE TABLE IF NOT EXISTS auth.email_change_tokens (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    new_email   VARCHAR(100) NOT NULL,
    token_hash  CHAR(64) NOT NULL,
    mailed      BOOLEAN NOT NULL DEFAULT false,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_email_change_tokens_token_hash UNIQUE (token_hash)
);
CREATE INDEX IF NOT EXISTS idx_email_change_tokens_user_id ON auth.email_change_tokens (user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_email_change_tokens_created_at ON auth.email_change_tokens (created_at);
