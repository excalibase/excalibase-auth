ALTER TABLE email_otps DROP FOREIGN KEY fk_email_otps_link_user;
ALTER TABLE email_otps DROP COLUMN link_user_id;
ALTER TABLE auth_codes DROP COLUMN link_provider, DROP COLUMN link_subject, DROP COLUMN link_email;
ALTER TABLE refresh_tokens DROP COLUMN last_auth_at;
