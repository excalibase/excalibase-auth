-- EXC-662: the twin of Postgres 000011.
ALTER TABLE refresh_tokens ADD COLUMN last_auth_at DATETIME(6) NULL;

ALTER TABLE auth_codes
    ADD COLUMN link_provider VARCHAR(32)  NULL,
    ADD COLUMN link_subject  VARCHAR(255) NULL,
    ADD COLUMN link_email    VARCHAR(255) NULL;

ALTER TABLE email_otps
    ADD COLUMN link_user_id BIGINT NULL,
    ADD CONSTRAINT fk_email_otps_link_user FOREIGN KEY (link_user_id) REFERENCES users (id) ON DELETE CASCADE;
