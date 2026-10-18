-- EXC-557: a verification link proves the address; only a link minted by the
-- sign-up that set the current password proves that password too. Links from
-- resend (and any minted before this column) lead to a password reset.
ALTER TABLE auth.email_verification_tokens
    ADD COLUMN IF NOT EXISTS confirms_password BOOLEAN NOT NULL DEFAULT false;
