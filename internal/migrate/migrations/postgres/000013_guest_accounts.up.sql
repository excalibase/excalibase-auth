-- EXC-662: guest accounts. A guest has no address and no password until it is
-- upgraded by proving an address or linking a provider; it keeps its id.
ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS is_guest BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS idx_users_guests ON auth.users (id) WHERE is_guest;

-- One row per guest sign-up, kept a day so the per-client and per-project
-- budgets are counted the same on every replica.
CREATE TABLE IF NOT EXISTS auth.guest_sign_ups (
    id         BIGSERIAL PRIMARY KEY,
    ip         VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_guest_sign_ups_ip ON auth.guest_sign_ups (ip, created_at);
CREATE INDEX IF NOT EXISTS idx_guest_sign_ups_created_at ON auth.guest_sign_ups (created_at);

-- Every guest sign-up locks this one row so the budgets are counted one at a
-- time; cleaned_at is when inactive guests were last removed.
CREATE TABLE IF NOT EXISTS auth.guest_lock (
    id         SMALLINT PRIMARY KEY CHECK (id = 1),
    cleaned_at TIMESTAMPTZ
);
INSERT INTO auth.guest_lock (id) VALUES (1) ON CONFLICT DO NOTHING;
