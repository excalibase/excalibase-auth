-- EXC-662: the twin of Postgres 000013.
ALTER TABLE users ADD COLUMN is_guest BOOLEAN NOT NULL DEFAULT FALSE, ADD KEY idx_users_guests (is_guest, id);

CREATE TABLE IF NOT EXISTS guest_sign_ups (
    id         BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ip         VARCHAR(64) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_guest_sign_ups_ip (ip, created_at),
    KEY idx_guest_sign_ups_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;

CREATE TABLE IF NOT EXISTS guest_lock (
    id         SMALLINT    NOT NULL PRIMARY KEY,
    cleaned_at DATETIME(6) NULL,
    CONSTRAINT ck_guest_lock_one CHECK (id = 1)
) ENGINE=InnoDB;
INSERT IGNORE INTO guest_lock (id) VALUES (1);

ALTER TABLE email_change_tokens ADD COLUMN guest_client VARCHAR(64) NULL,
    ADD KEY idx_email_change_tokens_guest (guest_client, created_at);
