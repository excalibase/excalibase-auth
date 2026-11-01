-- EXC-662: TOTP second factors. A secret is stored sealed with the project's
-- key (AES-256-GCM bound to the account and factor), never in the clear.
CREATE TABLE IF NOT EXISTS auth.mfa_factors (
    id             UUID         PRIMARY KEY,
    user_id        BIGINT       NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    factor_type    VARCHAR(16)  NOT NULL DEFAULT 'totp' CHECK (factor_type = 'totp'),
    friendly_name  VARCHAR(100) NOT NULL,
    secret_enc     BYTEA        NOT NULL,
    status         VARCHAR(16)  NOT NULL DEFAULT 'unverified' CHECK (status IN ('unverified', 'verified')),
    -- The newest time step a code was accepted for; no step is accepted twice.
    last_used_step BIGINT,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_mfa_factors_name UNIQUE (user_id, friendly_name)
);

CREATE TABLE IF NOT EXISTS auth.mfa_challenges (
    id         UUID        PRIMARY KEY,
    factor_id  UUID        NOT NULL REFERENCES auth.mfa_factors(id) ON DELETE CASCADE,
    ip         VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_factor ON auth.mfa_challenges (factor_id, expires_at);

-- Recovery codes are kept as keyed hashes and spent once.
CREATE TABLE IF NOT EXISTS auth.mfa_recovery_codes (
    id         BIGSERIAL   PRIMARY KEY,
    user_id    BIGINT      NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    code_hash  CHAR(64)    NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_mfa_recovery_codes UNIQUE (user_id, code_hash)
);

-- Wrong codes, counted here so every replica shares one budget: per factor,
-- or per account (factor_id NULL) for recovery codes.
CREATE TABLE IF NOT EXISTS auth.mfa_failures (
    id        BIGSERIAL   PRIMARY KEY,
    user_id   BIGINT      NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    factor_id UUID        REFERENCES auth.mfa_factors(id) ON DELETE CASCADE,
    failed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mfa_failures_user ON auth.mfa_failures (user_id, failed_at);
CREATE INDEX IF NOT EXISTS idx_mfa_failures_factor ON auth.mfa_failures (factor_id);

-- A session's assurance level and how it signed in, kept across refreshes.
ALTER TABLE auth.refresh_tokens
    ADD COLUMN IF NOT EXISTS aal SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS amr VARCHAR(100) NOT NULL DEFAULT '';
