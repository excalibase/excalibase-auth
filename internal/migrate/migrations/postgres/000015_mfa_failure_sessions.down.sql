DROP INDEX IF EXISTS auth.idx_mfa_failures_family;
ALTER TABLE auth.mfa_failures DROP COLUMN IF EXISTS family_id;
