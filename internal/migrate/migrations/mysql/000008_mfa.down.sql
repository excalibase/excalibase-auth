ALTER TABLE refresh_tokens DROP COLUMN amr, DROP COLUMN aal;
DROP TABLE IF EXISTS mfa_failures;
DROP TABLE IF EXISTS mfa_recovery_codes;
DROP TABLE IF EXISTS mfa_challenges;
DROP TABLE IF EXISTS mfa_factors;
