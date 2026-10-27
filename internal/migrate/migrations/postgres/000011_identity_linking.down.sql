ALTER TABLE auth.email_otps DROP COLUMN IF EXISTS link_user_id;
ALTER TABLE auth.auth_codes
    DROP COLUMN IF EXISTS link_provider,
    DROP COLUMN IF EXISTS link_subject,
    DROP COLUMN IF EXISTS link_email;
ALTER TABLE auth.refresh_tokens DROP COLUMN IF EXISTS last_auth_at;
