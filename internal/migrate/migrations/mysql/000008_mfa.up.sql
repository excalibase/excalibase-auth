-- EXC-662: the twin of Postgres 000014.
CREATE TABLE IF NOT EXISTS mfa_factors (
    id             CHAR(36)     NOT NULL PRIMARY KEY,
    user_id        BIGINT       NOT NULL,
    factor_type    VARCHAR(16)  NOT NULL DEFAULT 'totp',
    friendly_name  VARCHAR(100) NOT NULL,
    secret_enc     VARBINARY(255) NOT NULL,
    status         VARCHAR(16)  NOT NULL DEFAULT 'unverified',
    last_used_step BIGINT       NULL,
    created_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_mfa_factors_name UNIQUE (user_id, friendly_name),
    CONSTRAINT ck_mfa_factors_type CHECK (factor_type = 'totp'),
    CONSTRAINT ck_mfa_factors_status CHECK (status IN ('unverified', 'verified')),
    CONSTRAINT fk_mfa_factors_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;

CREATE TABLE IF NOT EXISTS mfa_challenges (
    id         CHAR(36)    NOT NULL PRIMARY KEY,
    factor_id  CHAR(36)    NOT NULL,
    ip         VARCHAR(64) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at DATETIME(6) NOT NULL,
    KEY idx_mfa_challenges_factor (factor_id, expires_at),
    CONSTRAINT fk_mfa_challenges_factor FOREIGN KEY (factor_id) REFERENCES mfa_factors (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id         BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id    BIGINT      NOT NULL,
    code_hash  CHAR(64)    NOT NULL,
    used_at    DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_mfa_recovery_codes UNIQUE (user_id, code_hash),
    CONSTRAINT fk_mfa_recovery_codes_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;

CREATE TABLE IF NOT EXISTS mfa_failures (
    id        BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id   BIGINT      NOT NULL,
    factor_id CHAR(36)    NULL,
    failed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_mfa_failures_user (user_id, failed_at),
    CONSTRAINT fk_mfa_failures_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_mfa_failures_factor FOREIGN KEY (factor_id) REFERENCES mfa_factors (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;

ALTER TABLE refresh_tokens ADD COLUMN aal SMALLINT NOT NULL DEFAULT 1, ADD COLUMN amr VARCHAR(100) NOT NULL DEFAULT '';
