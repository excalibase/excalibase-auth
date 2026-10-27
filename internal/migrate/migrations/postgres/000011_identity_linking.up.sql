-- EXC-662: a signed-in user links Google, GitHub or another address to the
-- account. Linking needs a recent sign-in, so a session keeps when its owner
-- signed in across rotations; a link is written only when the app redeems its
-- code or spends its email code with the PKCE verifier.
ALTER TABLE auth.refresh_tokens ADD COLUMN IF NOT EXISTS last_auth_at TIMESTAMPTZ;

ALTER TABLE auth.auth_codes
    ADD COLUMN IF NOT EXISTS link_provider VARCHAR(32),
    ADD COLUMN IF NOT EXISTS link_subject  VARCHAR(255),
    ADD COLUMN IF NOT EXISTS link_email    VARCHAR(255);

ALTER TABLE auth.email_otps
    ADD COLUMN IF NOT EXISTS link_user_id BIGINT REFERENCES auth.users(id) ON DELETE CASCADE;
