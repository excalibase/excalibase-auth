-- EXC-662: sign-in through Google or GitHub. An account made by a provider has
-- no password, so password may be NULL; email may be NULL for the anonymous
-- accounts of a later step. Nothing writes a NULL email yet.

ALTER TABLE auth.users ALTER COLUMN password DROP NOT NULL;
ALTER TABLE auth.users ALTER COLUMN email DROP NOT NULL;

-- A provider account (provider + its stable subject id) joined to one user.
CREATE TABLE IF NOT EXISTS auth.identities (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    provider        VARCHAR(32)  NOT NULL,
    subject         VARCHAR(255) NOT NULL,
    email           VARCHAR(255),
    email_verified  BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_sign_in_at TIMESTAMPTZ,
    CONSTRAINT uq_identities_provider_subject UNIQUE (provider, subject)
);
CREATE INDEX IF NOT EXISTS idx_identities_user_id ON auth.identities(user_id);

-- A sign-in between /authorize and the provider's callback; the state is
-- stored only as its SHA-256 and spent once.
CREATE TABLE IF NOT EXISTS auth.flow_states (
    state_hash            CHAR(64) PRIMARY KEY,
    provider              VARCHAR(32)  NOT NULL,
    idp_code_verifier     VARCHAR(128) NOT NULL,
    nonce                 VARCHAR(128) NOT NULL DEFAULT '',
    client_code_challenge VARCHAR(128) NOT NULL,
    redirect_to           TEXT NOT NULL,
    link_user_id          BIGINT REFERENCES auth.users(id) ON DELETE CASCADE,
    expires_at            TIMESTAMPTZ NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_flow_states_expires_at ON auth.flow_states(expires_at);

-- The code handed back to the app, redeemed once with the PKCE verifier.
CREATE TABLE IF NOT EXISTS auth.auth_codes (
    code_hash      CHAR(64) PRIMARY KEY,
    user_id        BIGINT NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    code_challenge VARCHAR(128) NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    consumed_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires_at ON auth.auth_codes(expires_at);
