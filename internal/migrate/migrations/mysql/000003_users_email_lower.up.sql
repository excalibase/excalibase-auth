-- EXC-662: the twin of Postgres 000009.
CREATE INDEX idx_users_email_lower ON users ((LOWER(email)));
