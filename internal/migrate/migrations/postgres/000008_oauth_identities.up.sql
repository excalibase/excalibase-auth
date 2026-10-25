-- EXC-662: sign-in through Google or GitHub. Accounts made by a provider carry
-- no password. Anonymous accounts of a later step carry no address; nothing
-- writes one without an address yet.

ALTER TABLE auth.users ALTER COLUMN password DROP NOT NULL;
ALTER TABLE auth.users ALTER COLUMN email DROP NOT NULL;

-- When the address was proven. 000003 marked every older account verified with
-- no proof; only a redeemed link or a provider sign-in sets this, and only an
-- account with it is linked to a provider sign-in.
ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;
UPDATE auth.users u SET email_verified_at = proof.at
FROM (SELECT user_id, max(consumed_at) AS at FROM auth.email_verification_tokens
      WHERE consumed_at IS NOT NULL GROUP BY user_id) proof
WHERE u.id = proof.user_id AND u.email_verified AND u.email_verified_at IS NULL;

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
