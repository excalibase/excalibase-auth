-- EXC-662: the twin of Postgres 000010.
CREATE TABLE IF NOT EXISTS email_otps (
    id             BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    email          VARCHAR(255) NOT NULL,
    kind           VARCHAR(16)  NOT NULL,
    link_hash      CHAR(64)     NULL,
    code_hmac      CHAR(64)     NULL,
    code_challenge VARCHAR(128) NOT NULL,
    create_user    BOOLEAN      NOT NULL DEFAULT FALSE,
    mailed         BOOLEAN      NOT NULL DEFAULT FALSE,
    ip             VARCHAR(64)  NULL,
    attempts       INT          NOT NULL DEFAULT 0,
    expires_at     DATETIME(6)  NOT NULL,
    consumed_at    DATETIME(6)  NULL,
    created_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_email_otps_link_hash UNIQUE (link_hash),
    KEY idx_email_otps_email ((LOWER(email)), created_at),
    KEY idx_email_otps_created_at (created_at),
    KEY idx_email_otps_ip (ip, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;

CREATE TABLE IF NOT EXISTS email_otp_lock (
    id SMALLINT NOT NULL PRIMARY KEY,
    CONSTRAINT ck_email_otp_lock_one CHECK (id = 1)
) ENGINE=InnoDB;
INSERT IGNORE INTO email_otp_lock (id) VALUES (1);

CREATE TABLE IF NOT EXISTS audit_log (
    id         BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id    BIGINT      NULL,
    event      VARCHAR(32) NOT NULL,
    method     VARCHAR(32) NULL,
    ip         VARCHAR(64) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_audit_log_user_id (user_id),
    KEY idx_audit_log_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
