-- A MySQL project's end users (ADR 0041, EXC-626), in the auth database of the
-- project's own instance. One migration reaches what Postgres migrations
-- 000001-000007 build; the two trees are versioned separately.
--
-- utf8mb4_0900_bin compares text byte for byte with no padding, as Postgres
-- does: an address, its upper-case spelling and the same address with a
-- trailing space are three accounts; token hashes match exactly.
-- Times are DATETIME(6) written in UTC (every connection sets time_zone).

CREATE TABLE IF NOT EXISTS users (
    id             BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    email          VARCHAR(100) NOT NULL,
    password       VARCHAR(255) NOT NULL,
    full_name      VARCHAR(100) NOT NULL,
    role           VARCHAR(63)  NOT NULL DEFAULT 'user',
    allowed_roles  JSON         NULL,                    -- NULL means only role
    enabled        BOOLEAN      NOT NULL DEFAULT TRUE,
    email_verified BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_login_at  DATETIME(6)  NULL,
    CONSTRAINT uq_users_email UNIQUE (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    token_hash  CHAR(64)    NOT NULL,                    -- SHA-256 hex; never the token
    family_id   CHAR(36)    NOT NULL,                    -- one login
    user_id     BIGINT      NOT NULL,
    expiry_date DATETIME(6) NOT NULL,
    created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    revoked     BOOLEAN     NOT NULL DEFAULT FALSE,
    CONSTRAINT uq_refresh_tokens_token_hash UNIQUE (token_hash),
    KEY idx_refresh_tokens_family_id (family_id),
    KEY idx_refresh_tokens_user_id (user_id),
    CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;

CREATE TABLE IF NOT EXISTS api_keys (
    id           BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    key_hash     VARCHAR(64)  NOT NULL,                  -- SHA-256 hex
    key_prefix   VARCHAR(24)  NOT NULL,                  -- for display
    key_type     VARCHAR(16)  NOT NULL,
    name         VARCHAR(100) NULL,
    created_by   BIGINT       NULL,
    created_at   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_used_at DATETIME(6)  NULL,
    revoked_at   DATETIME(6)  NULL,
    revoked_by   BIGINT       NULL,
    CONSTRAINT uq_api_keys_key_hash UNIQUE (key_hash),
    CONSTRAINT chk_api_keys_key_type CHECK (key_type IN ('publishable', 'secret')),
    KEY idx_api_keys_prefix (key_prefix),
    KEY idx_api_keys_created_by (created_by),
    CONSTRAINT fk_api_keys_created_by FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_api_keys_revoked_by FOREIGN KEY (revoked_by) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id                BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    token_hash        CHAR(64)    NOT NULL,
    user_id           BIGINT      NOT NULL,
    expires_at        DATETIME(6) NOT NULL,
    consumed_at       DATETIME(6) NULL,                  -- set once redeemed: single use
    confirms_password BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_email_verification_tokens_token_hash UNIQUE (token_hash),
    KEY idx_email_verification_tokens_user_id (user_id),
    CONSTRAINT fk_email_verification_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id          BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    token_hash  CHAR(64)    NOT NULL,
    user_id     BIGINT      NOT NULL,
    expires_at  DATETIME(6) NOT NULL,
    consumed_at DATETIME(6) NULL,
    created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_password_reset_tokens_token_hash UNIQUE (token_hash),
    KEY idx_password_reset_tokens_user_id (user_id),
    CONSTRAINT fk_password_reset_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;

CREATE TABLE IF NOT EXISTS role_changes (
    id                BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id           BIGINT      NOT NULL,
    old_role          TEXT        NOT NULL,
    new_role          TEXT        NOT NULL,
    old_allowed_roles JSON        NOT NULL,
    new_allowed_roles JSON        NOT NULL,
    actor             TEXT        NOT NULL,              -- studio:<platform user id> | service-key:<api key id>
    changed_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_role_changes_user_id (user_id),
    CONSTRAINT fk_role_changes_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
