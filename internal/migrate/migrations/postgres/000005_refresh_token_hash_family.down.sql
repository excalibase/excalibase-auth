-- Hashes cannot be turned back into tokens, so every session ends on rollback.
DELETE FROM auth.refresh_tokens;

DROP INDEX IF EXISTS auth.idx_refresh_tokens_family_id;
DROP INDEX IF EXISTS auth.idx_refresh_tokens_token_hash;
ALTER TABLE auth.refresh_tokens DROP COLUMN IF EXISTS family_id;
ALTER TABLE auth.refresh_tokens DROP COLUMN IF EXISTS token_hash;
ALTER TABLE auth.refresh_tokens ADD COLUMN IF NOT EXISTS token VARCHAR(255) NOT NULL UNIQUE;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON auth.refresh_tokens(token);
