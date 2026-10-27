package mysqlstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/excalibase/auth/internal/store"
)

const endChangesQuery = "UPDATE email_change_tokens SET consumed_at = NOW(6) WHERE user_id = ? AND consumed_at IS NULL"

func (s *Store) SaveEmailChange(ctx context.Context, change store.EmailChange, limits store.EmailChangeLimits) (store.EmailChangeMail, error) {
	var mail store.EmailChangeMail
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if err := linkTarget(tx.QueryRowContext(ctx, linkTargetLockedQuery, change.UserID)); err != nil {
			return err
		}
		var today, recent sql.NullInt64
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*), SUM(created_at > NOW(6) - INTERVAL ? MICROSECOND) FROM email_change_tokens
			 WHERE user_id = ? AND created_at > NOW(6) - INTERVAL 1 DAY`,
			limits.MinInterval.Microseconds(), change.UserID).Scan(&today, &recent); err != nil {
			return err
		}
		if recent.Int64 > 0 || today.Int64 >= int64(limits.PerAccountDay) {
			return store.ErrRateLimited
		}
		if change.GuestClient != "" {
			if err := guestChangeAllowed(ctx, tx, change.GuestClient, limits); err != nil {
				return err
			}
		}
		var err error
		if mail, err = changeMail(ctx, tx, change, limits.PerProjectDay); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, endChangesQuery, change.UserID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM email_change_tokens WHERE created_at < NOW(6) - INTERVAL 1 DAY"); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO email_change_tokens (user_id, new_email, token_hash, mailed, expires_at, guest_client)
			 VALUES (?, ?, ?, ?, ?, NULLIF(?, ''))`,
			change.UserID, change.NewEmail, change.TokenHash, mail.Notice, change.ExpiresAt.UTC(), change.GuestClient)
		return err
	})
	if err != nil {
		return store.EmailChangeMail{}, err
	}
	return mail, nil
}

// changeMail decides the mails; see pgstore.
func changeMail(ctx context.Context, tx *sql.Tx, change store.EmailChange, perProjectDay int) (store.EmailChangeMail, error) {
	var (
		held bool
		sent int
	)
	err := tx.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM users WHERE LOWER(email) = LOWER(?) AND id <> ?
		                AND ((email_verified AND email_verified_at IS NOT NULL) OR NOT enabled))
		     OR EXISTS (SELECT 1 FROM identities WHERE provider = ? AND subject = ? AND user_id <> ?),
		        (SELECT COUNT(*) FROM email_change_tokens WHERE mailed AND created_at > NOW(6) - INTERVAL 1 DAY)`,
		change.NewEmail, change.UserID, store.EmailProvider, store.AddressKey(change.NewEmail), change.UserID).Scan(&held, &sent)
	if err != nil {
		return store.EmailChangeMail{}, err
	}
	notice := sent < perProjectDay
	return store.EmailChangeMail{Notice: notice, Link: notice && !held}, nil
}

func (s *Store) ConfirmEmailChange(ctx context.Context, userID int64, tokenHash string) (store.ChangedEmail, error) {
	var changed store.ChangedEmail
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx,
			`SELECT user_id, new_email FROM email_change_tokens
			 WHERE token_hash = ? AND user_id = ? AND consumed_at IS NULL AND expires_at > NOW(6) FOR UPDATE`,
			tokenHash, userID).Scan(&changed.UserID, &changed.NewEmail); err != nil {
			return notFound(err)
		}
		var enabled bool
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(email, ''), enabled FROM users WHERE id = ? FOR UPDATE",
			changed.UserID).Scan(&changed.OldEmail, &enabled); err != nil {
			return notFound(err)
		}
		if !enabled {
			return store.ErrAccountDisabled
		}
		if err := releaseOwnLinkedAddress(ctx, tx, changed); err != nil {
			return err
		}
		var err error
		if changed.Replaced, err = claimAddress(ctx, tx, changed.UserID, changed.NewEmail); err != nil {
			return referenced(err)
		}
		if _, err := tx.ExecContext(ctx,
			"UPDATE users SET email = ?, email_verified = TRUE, email_verified_at = NOW(6), updated_at = NOW(6) WHERE id = ?",
			changed.NewEmail, changed.UserID); err != nil {
			return err
		}
		if err := upgradeGuest(ctx, tx, changed.UserID, changed.NewEmail); err != nil {
			return err
		}
		// Links mailed to the old address must not act on the account any more.
		for _, statement := range []string{endChangesQuery, tokenTables[store.PasswordReset].invalidate,
			tokenTables[store.EmailVerification].invalidate} {
			if _, err := tx.ExecContext(ctx, statement, changed.UserID); err != nil {
				return err
			}
		}
		return nil
	})
	return changed, err
}

// releaseOwnLinkedAddress drops the account's own link to the address it moves
// to; a link of another account keeps the address its own.
func releaseOwnLinkedAddress(ctx context.Context, tx *sql.Tx, changed store.ChangedEmail) error {
	var owner int64
	err := tx.QueryRowContext(ctx, "SELECT user_id FROM identities WHERE provider = ? AND subject = ? FOR UPDATE",
		store.EmailProvider, store.AddressKey(changed.NewEmail)).Scan(&owner)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return err
	case owner != changed.UserID:
		return store.ErrIdentityExists
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM identities WHERE provider = ? AND subject = ?",
		store.EmailProvider, store.AddressKey(changed.NewEmail))
	return err
}

// guestChangeAllowed counts a guest's request, under the guest sign-up lock,
// against its client's and the guests' share of the project's budget.
func guestChangeAllowed(ctx context.Context, tx *sql.Tx, client string, limits store.EmailChangeLimits) error {
	var locked int
	if err := tx.QueryRowContext(ctx, "SELECT id FROM guest_lock WHERE id = 1 FOR UPDATE").Scan(&locked); err != nil {
		return err
	}
	var fromClient, guests int
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(guest_client = ?), 0), COALESCE(SUM(mailed), 0)
		 FROM email_change_tokens WHERE guest_client IS NOT NULL AND created_at > NOW(6) - INTERVAL 1 DAY`,
		client).Scan(&fromClient, &guests); err != nil {
		return err
	}
	if fromClient >= limits.PerGuestClientDay || guests >= limits.GuestPerProjectDay {
		return store.ErrRateLimited
	}
	return nil
}
