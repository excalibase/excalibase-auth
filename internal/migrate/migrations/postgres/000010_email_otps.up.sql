-- EXC-662: sign-in with an emailed link or six-digit code. One row per send: a
-- link is kept as its SHA-256, a code as an HMAC under a key the database never
-- holds. Rows stay a day so the send budgets can be counted from them.
CREATE TABLE IF NOT EXISTS auth.email_otps (
    id             BIGSERIAL PRIMARY KEY,
    email          VARCHAR(255) NOT NULL,
    kind           VARCHAR(16)  NOT NULL,
    link_hash      CHAR(64),
    code_hmac      CHAR(64),
    code_challenge VARCHAR(128) NOT NULL,
    create_user    BOOLEAN NOT NULL DEFAULT false,
    mailed         BOOLEAN NOT NULL DEFAULT false,
    ip             VARCHAR(64),
    attempts       INT NOT NULL DEFAULT 0,
    expires_at     TIMESTAMPTZ NOT NULL,
    consumed_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_email_otps_link_hash UNIQUE (link_hash)
);
CREATE INDEX IF NOT EXISTS idx_email_otps_email ON auth.email_otps (lower(email), created_at);
CREATE INDEX IF NOT EXISTS idx_email_otps_created_at ON auth.email_otps (created_at);
CREATE INDEX IF NOT EXISTS idx_email_otps_ip ON auth.email_otps (ip, created_at);

-- Every send locks this one row, so replicas count the budgets one at a time.
CREATE TABLE IF NOT EXISTS auth.email_otp_lock (
    id SMALLINT PRIMARY KEY CHECK (id = 1)
);
INSERT INTO auth.email_otp_lock (id) VALUES (1) ON CONFLICT DO NOTHING;

-- Who signed in, how and from where. No foreign key: the trail outlives an
-- account that is replaced or deleted.
CREATE TABLE IF NOT EXISTS auth.audit_log (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT,
    event      VARCHAR(32) NOT NULL,
    method     VARCHAR(32),
    ip         VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON auth.audit_log (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON auth.audit_log (created_at);
