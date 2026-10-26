package mysqlstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/excalibase/auth/internal/store"
)

func (s *Store) SaveEmailOTP(ctx context.Context, otp store.EmailOTP, limits store.OTPLimits) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT INTO email_otp_lock (id) VALUES (1) ON DUPLICATE KEY UPDATE id = id"); err != nil {
			return err
		}
		if err := withinOTPLimits(ctx, tx, otp.Email, limits); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM email_otps WHERE created_at < NOW(6) - INTERVAL 1 DAY"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			"UPDATE email_otps SET consumed_at = NOW(6) WHERE LOWER(email) = LOWER(?) AND consumed_at IS NULL", otp.Email); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO email_otps (email, kind, link_hash, code_hmac, code_challenge, create_user, expires_at)
			 VALUES (?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?)`,
			otp.Email, otp.Kind, otp.LinkHash, otp.CodeHMAC, otp.CodeChallenge, otp.CreateUser, otp.ExpiresAt.UTC())
		return err
	})
}

// withinOTPLimits counts the sends the budgets allow, under the lock row.
func withinOTPLimits(ctx context.Context, tx *sql.Tx, email string, limits store.OTPLimits) error {
	var recent, lastHour, lastDay sql.NullInt64
	if err := tx.QueryRowContext(ctx,
		`SELECT SUM(LOWER(email) = LOWER(?) AND created_at > NOW(6) - INTERVAL ? MICROSECOND),
		        SUM(LOWER(email) = LOWER(?) AND created_at > NOW(6) - INTERVAL 1 HOUR),
		        COUNT(*)
		 FROM email_otps WHERE created_at > NOW(6) - INTERVAL 1 DAY`,
		email, limits.MinInterval.Microseconds(), email).Scan(&recent, &lastHour, &lastDay); err != nil {
		return err
	}
	if recent.Int64 > 0 || lastHour.Int64 >= int64(limits.PerAddressHour) || lastDay.Int64 >= int64(limits.PerProjectDay) {
		return store.ErrRateLimited
	}
	return nil
}

func (s *Store) RedeemEmailOTP(ctx context.Context, lookup store.OTPLookup, maxAttempts int, check func(store.EmailOTP) bool) (store.EmailOTP, error) {
	var (
		otp      store.EmailOTP
		accepted bool
	)
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		const columns = `SELECT id, email, kind, COALESCE(link_hash, ''), COALESCE(code_hmac, ''), code_challenge, create_user, attempts, expires_at
			FROM email_otps WHERE consumed_at IS NULL AND expires_at > NOW(6) AND `
		var row *sql.Row
		if lookup.LinkHash != "" {
			row = tx.QueryRowContext(ctx, columns+"link_hash = ? AND kind = ? FOR UPDATE", lookup.LinkHash, store.OTPMagicLink)
		} else {
			row = tx.QueryRowContext(ctx, columns+`LOWER(email) = LOWER(?) AND kind = ? AND attempts < ?
				ORDER BY created_at DESC, id DESC LIMIT 1 FOR UPDATE`, lookup.Email, store.OTPEmailCode, maxAttempts)
		}
		var id int64
		if err := row.Scan(&id, &otp.Email, &otp.Kind, &otp.LinkHash, &otp.CodeHMAC, &otp.CodeChallenge,
			&otp.CreateUser, &otp.Attempts, &otp.ExpiresAt); err != nil {
			return notFound(err)
		}
		accepted = check(otp)
		spent := accepted || otp.Kind == store.OTPMagicLink || otp.Attempts+1 >= maxAttempts
		attempts := otp.Attempts
		if !accepted {
			attempts++
		}
		_, err := tx.ExecContext(ctx,
			"UPDATE email_otps SET attempts = ?, consumed_at = IF(?, NOW(6), NULL) WHERE id = ?", attempts, spent, id)
		return err
	})
	if err != nil {
		return store.EmailOTP{}, err
	}
	if !accepted {
		return store.EmailOTP{}, store.ErrNotFound
	}
	return otp, nil
}

func (s *Store) SignInWithEmail(ctx context.Context, email, fullName string, allowCreate bool) (store.Account, store.IdentityOutcome, error) {
	var (
		account store.Account
		outcome store.IdentityOutcome
	)
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		claim := store.IdentityClaim{Email: email, FullName: fullName}
		userID, verified, err := accountForAddress(ctx, tx, email)
		outcome = store.IdentityKnown
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if !allowCreate {
				return store.ErrSignupsDisabled
			}
			userID, err = createProviderUser(ctx, tx, claim)
			outcome = store.IdentityCreated
		case err != nil:
			return err
		case !verified:
			userID, err = takeOver(ctx, tx, userID, claim)
			outcome = store.IdentityTookOver
		}
		if err != nil {
			return err
		}
		account, err = scanAccount(tx.QueryRowContext(ctx, "SELECT "+accountColumns+" FROM users WHERE id = ?", userID))
		return err
	})
	if err != nil {
		return store.Account{}, 0, err
	}
	return account, outcome, nil
}

func (s *Store) AccountByAddress(ctx context.Context, email string) (store.Account, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, email = ?, FALSE FROM users WHERE LOWER(email) = LOWER(?) ORDER BY email = ? DESC, id LIMIT 2", email, email, email)
	if err != nil {
		return store.Account{}, err
	}
	defer rows.Close()
	var matches []store.AddressMatch
	for rows.Next() {
		var match store.AddressMatch
		if err := rows.Scan(&match.ID, &match.Exact, &match.Verified); err != nil {
			return store.Account{}, err
		}
		matches = append(matches, match)
	}
	if err := rows.Err(); err != nil {
		return store.Account{}, err
	}
	id, _, err := store.PickAddressMatch(matches, store.ErrNotFound)
	if err != nil {
		return store.Account{}, err
	}
	return s.AccountByID(ctx, id)
}

func (s *Store) RecordAudit(ctx context.Context, event store.AuditEvent) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO audit_log (user_id, event, method, ip) VALUES (NULLIF(?, 0), ?, NULLIF(?, ''), NULLIF(?, ''))",
		event.UserID, event.Event, event.Method, event.IP)
	return err
}
