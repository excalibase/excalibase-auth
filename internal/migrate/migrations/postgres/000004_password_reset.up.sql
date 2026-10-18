-- EXC-12: end-user password reset.
--
-- Same shape as email_verification_tokens: only the SHA-256 hash of the emailed
-- token is stored, consumed_at makes it single use, and the row is schema
-- qualified so the migration is safe under transaction pooling.

CREATE TABLE IF NOT EXISTS auth.password_reset_tokens (
    id          BIGSERIAL PRIMARY KEY,
    token_hash  CHAR(64) NOT NULL UNIQUE,
    user_id     BIGINT NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id
    ON auth.password_reset_tokens(user_id);
