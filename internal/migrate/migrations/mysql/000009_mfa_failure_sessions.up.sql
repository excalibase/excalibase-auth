-- EXC-662: the twin of Postgres 000015.
ALTER TABLE mfa_failures ADD COLUMN family_id CHAR(36) NULL, ADD KEY idx_mfa_failures_family (user_id, family_id, failed_at);
