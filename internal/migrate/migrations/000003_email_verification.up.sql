-- EXC-11: end-user email verification.
--
-- Schema-qualify every name so the migration is safe under transaction-pooled
-- connections where a session-level SET search_path can be lost mid-migration.

ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false;

-- Accounts that predate verification were created when no proof of address was
-- ever requested. Grandfather them in so a project that later switches on
-- requireEmailVerification does not lock out its whole existing user base.
-- This runs once, against exactly the rows present at migration time.
UPDATE auth.users SET email_verified = true;

CREATE TABLE IF NOT EXISTS auth.email_verification_tokens (
    id          BIGSERIAL PRIMARY KEY,
    token_hash  CHAR(64) NOT NULL UNIQUE,              -- SHA-256 hex of the emailed token
    user_id     BIGINT NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,                           -- non-null once redeemed: single use
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_user_id
    ON auth.email_verification_tokens(user_id);
