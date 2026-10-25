-- EXC-662: provider sign-ins match an address whatever its case.
CREATE INDEX IF NOT EXISTS idx_users_email_lower ON auth.users (lower(email));
