ALTER TABLE auth.refresh_tokens DROP COLUMN IF EXISTS amr, DROP COLUMN IF EXISTS aal;
DROP TABLE IF EXISTS auth.mfa_failures;
DROP TABLE IF EXISTS auth.mfa_recovery_codes;
DROP TABLE IF EXISTS auth.mfa_challenges;
DROP TABLE IF EXISTS auth.mfa_factors;
