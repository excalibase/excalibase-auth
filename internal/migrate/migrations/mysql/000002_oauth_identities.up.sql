-- EXC-662: sign-in through Google or GitHub; the twin of Postgres 000008.

ALTER TABLE users MODIFY password VARCHAR(255) NULL, MODIFY email VARCHAR(100) NULL;

CREATE TABLE IF NOT EXISTS identities (
    id              BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id         BIGINT       NOT NULL,
    provider        VARCHAR(32)  NOT NULL,
    subject         VARCHAR(255) NOT NULL,
    email           VARCHAR(255) NULL,
    email_verified  BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_sign_in_at DATETIME(6)  NULL,
    CONSTRAINT uq_identities_provider_subject UNIQUE (provider, subject),
    KEY idx_identities_user_id (user_id),
    CONSTRAINT fk_identities_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;

CREATE TABLE IF NOT EXISTS flow_states (
    state_hash            CHAR(64)     NOT NULL PRIMARY KEY,
    provider              VARCHAR(32)  NOT NULL,
    idp_code_verifier     VARCHAR(128) NOT NULL,
    nonce                 VARCHAR(128) NOT NULL DEFAULT '',
    client_code_challenge VARCHAR(128) NOT NULL,
    redirect_to           TEXT         NOT NULL,
    link_user_id          BIGINT       NULL,
    expires_at            DATETIME(6)  NOT NULL,
    created_at            DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_flow_states_expires_at (expires_at),
    CONSTRAINT fk_flow_states_link_user FOREIGN KEY (link_user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;

CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash      CHAR(64)     NOT NULL PRIMARY KEY,
    user_id        BIGINT       NOT NULL,
    code_challenge VARCHAR(128) NOT NULL,
    expires_at     DATETIME(6)  NOT NULL,
    consumed_at    DATETIME(6)  NULL,
    created_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_auth_codes_expires_at (expires_at),
    CONSTRAINT fk_auth_codes_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
