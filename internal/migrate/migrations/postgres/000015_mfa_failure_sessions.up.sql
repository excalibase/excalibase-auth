-- EXC-662: wrong codes are budgeted per session (refresh family) too, so one
-- session that spent its budget does not lock the account's other sessions.
ALTER TABLE auth.mfa_failures ADD COLUMN IF NOT EXISTS family_id UUID;
CREATE INDEX IF NOT EXISTS idx_mfa_failures_family ON auth.mfa_failures (user_id, family_id, failed_at);
