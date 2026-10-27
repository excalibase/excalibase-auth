package pgstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/excalibase/auth/internal/store"
	"github.com/jackc/pgx/v5"
)

const endChangesQuery = "UPDATE auth.email_change_tokens SET consumed_at = NOW() WHERE user_id = $1 AND consumed_at IS NULL"

func (s *Store) SaveEmailChange(ctx context.Context, change store.EmailChange, limits store.EmailChangeLimits) (store.EmailChangeMail, error) {
	var none store.EmailChangeMail
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return none, fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)

	if err := linkTarget(ctx, tx.QueryRow(ctx, linkTargetLockedQuery, change.UserID)); err != nil {
		return none, err
	}
	var today int
	var recent bool
	if err := tx.QueryRow(ctx,
		`SELECT count(*), COALESCE(bool_or(created_at > NOW() - make_interval(secs => $2)), false)
		 FROM auth.email_change_tokens WHERE user_id = $1 AND created_at > NOW() - INTERVAL '1 day'`,
		change.UserID, limits.MinInterval.Seconds()).Scan(&today, &recent); err != nil {
		return none, err
	}
	if recent || today >= limits.PerAccountDay {
		return none, store.ErrRateLimited
	}
	mail, err := changeMail(ctx, tx, change, limits.PerProjectDay)
	if err != nil {
		return none, err
	}
	if _, err := tx.Exec(ctx, endChangesQuery, change.UserID); err != nil {
		return none, err
	}
	if _, err := tx.Exec(ctx, "DELETE FROM auth.email_change_tokens WHERE created_at < NOW() - INTERVAL '1 day'"); err != nil {
		return none, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO auth.email_change_tokens (user_id, new_email, token_hash, mailed, expires_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		change.UserID, change.NewEmail, change.TokenHash, mail.Notice, change.ExpiresAt); err != nil {
		return none, err
	}
	return mail, tx.Commit(ctx)
}

// changeMail mails nothing past the project's daily budget, and the link only
// when the address answers to no other proven or disabled account; the notice
// goes out either way, so the own inbox does not tell the two apart.
func changeMail(ctx context.Context, tx pgx.Tx, change store.EmailChange, perProjectDay int) (store.EmailChangeMail, error) {
	var held bool
	var sent int
	err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM auth.users WHERE lower(email) = lower($2) AND id <> $1
		                AND ((email_verified AND email_verified_at IS NOT NULL) OR NOT enabled))
		     OR EXISTS (SELECT 1 FROM auth.identities WHERE provider = $3 AND subject = $4 AND user_id <> $1),
		        (SELECT count(*) FROM auth.email_change_tokens WHERE mailed AND created_at > NOW() - INTERVAL '1 day')`,
		change.UserID, change.NewEmail, store.EmailProvider, store.AddressKey(change.NewEmail)).Scan(&held, &sent)
	if err != nil {
		return store.EmailChangeMail{}, err
	}
	notice := sent < perProjectDay
	return store.EmailChangeMail{Notice: notice, Link: notice && !held}, nil
}

func (s *Store) ConfirmEmailChange(ctx context.Context, userID int64, tokenHash string) (store.ChangedEmail, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return store.ChangedEmail{}, fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)

	var changed store.ChangedEmail
	if err := tx.QueryRow(ctx,
		`SELECT user_id, new_email FROM auth.email_change_tokens
		 WHERE token_hash = $1 AND user_id = $2 AND consumed_at IS NULL AND expires_at > NOW() FOR UPDATE`,
		tokenHash, userID).Scan(&changed.UserID, &changed.NewEmail); err != nil {
		return store.ChangedEmail{}, notFound(err)
	}
	var enabled bool
	if err := tx.QueryRow(ctx, "SELECT COALESCE(email, ''), enabled FROM auth.users WHERE id = $1 FOR UPDATE",
		changed.UserID).Scan(&changed.OldEmail, &enabled); err != nil {
		return store.ChangedEmail{}, notFound(err)
	}
	if !enabled {
		return store.ChangedEmail{}, store.ErrAccountDisabled
	}
	if err := releaseOwnLinkedAddress(ctx, tx, changed); err != nil {
		return store.ChangedEmail{}, err
	}
	if changed.Replaced, err = claimAddress(ctx, tx, changed.UserID, changed.NewEmail); err != nil {
		return store.ChangedEmail{}, referenced(err)
	}
	if _, err := tx.Exec(ctx,
		"UPDATE auth.users SET email = $2, email_verified = true, email_verified_at = NOW(), updated_at = NOW() WHERE id = $1",
		changed.UserID, changed.NewEmail); err != nil {
		return store.ChangedEmail{}, err
	}
	if err := upgradeGuest(ctx, tx, changed.UserID, changed.NewEmail); err != nil {
		return store.ChangedEmail{}, err
	}
	// Links mailed to the old address must not act on the account any more.
	for _, statement := range []string{endChangesQuery, tokenTables[store.PasswordReset].invalidate,
		tokenTables[store.EmailVerification].invalidate} {
		if _, err := tx.Exec(ctx, statement, changed.UserID); err != nil {
			return store.ChangedEmail{}, err
		}
	}
	return changed, tx.Commit(ctx)
}

// releaseOwnLinkedAddress drops the account's own link to the address it moves
// to; a link of another account keeps the address its own.
func releaseOwnLinkedAddress(ctx context.Context, tx pgx.Tx, changed store.ChangedEmail) error {
	var owner int64
	err := tx.QueryRow(ctx, "SELECT user_id FROM auth.identities WHERE provider = $1 AND subject = $2 FOR UPDATE",
		store.EmailProvider, store.AddressKey(changed.NewEmail)).Scan(&owner)
	switch {
	case err != nil:
		return ignoreNoRows(err)
	case owner != changed.UserID:
		return store.ErrIdentityExists
	}
	_, err = tx.Exec(ctx, "DELETE FROM auth.identities WHERE provider = $1 AND subject = $2",
		store.EmailProvider, store.AddressKey(changed.NewEmail))
	return err
}

func ignoreNoRows(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return err
}
