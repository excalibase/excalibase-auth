-- EXC-662: the twin of Postgres 000012.
ALTER TABLE users ADD COLUMN user_metadata JSON NULL, ADD COLUMN app_metadata JSON NULL;

CREATE TABLE IF NOT EXISTS email_change_tokens (
    id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id     BIGINT       NOT NULL,
    new_email   VARCHAR(100) NOT NULL,
    token_hash  CHAR(64)     NOT NULL,
    mailed      BOOLEAN      NOT NULL DEFAULT FALSE,
    expires_at  DATETIME(6)  NOT NULL,
    consumed_at DATETIME(6)  NULL,
    created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_email_change_tokens_token_hash UNIQUE (token_hash),
    KEY idx_email_change_tokens_user_id (user_id, created_at),
    KEY idx_email_change_tokens_created_at (created_at),
    CONSTRAINT fk_email_change_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
