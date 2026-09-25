-- Refresh tokens are kept only as SHA-256 hashes, and every token belongs to a
-- family (one login) so replaying a rotated token can revoke the whole session.

ALTER TABLE auth.refresh_tokens ADD COLUMN IF NOT EXISTS token_hash CHAR(64);
ALTER TABLE auth.refresh_tokens ADD COLUMN IF NOT EXISTS family_id UUID;

UPDATE auth.refresh_tokens
SET token_hash = encode(sha256(convert_to(token, 'UTF8')), 'hex'),
    family_id  = gen_random_uuid()
WHERE token_hash IS NULL;

ALTER TABLE auth.refresh_tokens ALTER COLUMN token_hash SET NOT NULL;
ALTER TABLE auth.refresh_tokens ALTER COLUMN family_id SET NOT NULL;
ALTER TABLE auth.refresh_tokens DROP COLUMN IF EXISTS token;

CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON auth.refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_id ON auth.refresh_tokens(family_id);
