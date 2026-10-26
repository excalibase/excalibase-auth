package mysqlstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/excalibase/auth/internal/store"
)

func (s *Store) SaveEmailOTP(ctx context.Context, otp store.EmailOTP, limits store.OTPLimits) (bool, error) {
	var mailed bool
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT INTO email_otp_lock (id) VALUES (1) ON DUPLICATE KEY UPDATE id = id"); err != nil {
			return err
		}
		var err error
		if mailed, err = withinOTPLimits(ctx, tx, otp, limits); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM email_otps WHERE created_at < NOW(6) - INTERVAL 1 DAY"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE email_otps SET consumed_at = NOW(6)
			 WHERE ? AND LOWER(email) = LOWER(?) AND code_challenge = ? AND consumed_at IS NULL`, mailed, otp.Email, otp.CodeChallenge); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO email_otps (email, kind, link_hash, code_hmac, code_challenge, create_user, mailed, ip, expires_at, link_user_id)
			 VALUES (?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?, NULLIF(?, ''), ?, NULLIF(?, 0))`,
			otp.Email, otp.Kind, otp.LinkHash, otp.CodeHMAC, otp.CodeChallenge, otp.CreateUser, mailed, otp.IP, otp.ExpiresAt.UTC(), otp.LinkUserID)
		return err
	})
	return mailed, err
}

// withinOTPLimits counts the sends the budgets allow, under the lock row, and
// says whether this one may be mailed.
func withinOTPLimits(ctx context.Context, tx *sql.Tx, otp store.EmailOTP, limits store.OTPLimits) (bool, error) {
	var recent, lastHour, fromIP, mailedToday, links sql.NullInt64
	if err := tx.QueryRowContext(ctx,
		`SELECT SUM(LOWER(email) = LOWER(?) AND created_at > NOW(6) - INTERVAL ? MICROSECOND),
		        SUM(LOWER(email) = LOWER(?) AND created_at > NOW(6) - INTERVAL 1 HOUR),
		        SUM(ip <=> ?),
		        SUM(mailed),
		        SUM(link_user_id <=> ?)
		 FROM email_otps WHERE created_at > NOW(6) - INTERVAL 1 DAY`,
		otp.Email, limits.MinInterval.Microseconds(), otp.Email, otp.IP, otp.LinkUserID).Scan(&recent, &lastHour, &fromIP, &mailedToday, &links); err != nil {
		return false, err
	}
	overLinks := otp.LinkUserID != 0 && limits.LinksPerAccountDay > 0 && links.Int64 >= int64(limits.LinksPerAccountDay)
	if recent.Int64 > 0 || lastHour.Int64 >= int64(limits.PerAddressHour) || fromIP.Int64 >= int64(limits.PerIPDay) || overLinks {
		return false, store.ErrRateLimited
	}
	return otp.Mailed && mailedToday.Int64 < int64(limits.PerProjectDay), nil
}

// The live sign-in lookups: an unspent, unexpired, mailed row.
const (
	liveLinkQuery = `SELECT id, email, kind, COALESCE(link_hash, ''), COALESCE(code_hmac, ''), code_challenge, create_user, attempts, expires_at,
		COALESCE(link_user_id, 0)
		FROM email_otps WHERE mailed AND consumed_at IS NULL AND expires_at > NOW(6)
		AND link_hash = ? AND kind = ? FOR UPDATE`
	liveCodeQuery = `SELECT id, email, kind, COALESCE(link_hash, ''), COALESCE(code_hmac, ''), code_challenge, create_user, attempts, expires_at,
		COALESCE(link_user_id, 0)
		FROM email_otps WHERE mailed AND consumed_at IS NULL AND expires_at > NOW(6)
		AND LOWER(email) = LOWER(?) AND kind = ? AND attempts < ? AND code_challenge = ?
		ORDER BY created_at DESC, id DESC LIMIT 1 FOR UPDATE`
)

func (s *Store) RedeemEmailOTP(ctx context.Context, lookup store.OTPLookup, limits store.OTPAttempts, check func(store.EmailOTP) bool) (store.EmailOTP, error) {
	var (
		otp      store.EmailOTP
		accepted bool
	)
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var row *sql.Row
		if lookup.LinkHash != "" {
			row = tx.QueryRowContext(ctx, liveLinkQuery, lookup.LinkHash, store.OTPMagicLink)
		} else {
			row = tx.QueryRowContext(ctx, liveCodeQuery, lookup.Email, store.OTPEmailCode, limits.PerCode, lookup.CodeChallenge)
		}
		var id int64
		if err := row.Scan(&id, &otp.Email, &otp.Kind, &otp.LinkHash, &otp.CodeHMAC, &otp.CodeChallenge,
			&otp.CreateUser, &otp.Attempts, &otp.ExpiresAt, &otp.LinkUserID); err != nil {
			return notFound(err)
		}
		accepted = check(otp)
		spent := accepted || otp.Kind == store.OTPMagicLink || otp.Attempts+1 >= limits.PerCode
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
	if linked, ok, err := s.linkedAccount(ctx, email); ok || err != nil {
		return linked, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+accountColumns+`, email = ? FROM users
		WHERE LOWER(email) = LOWER(?) ORDER BY email = ? DESC, id LIMIT 2`, email, email, email)
	if err != nil {
		return store.Account{}, err
	}
	defer rows.Close()
	var (
		accounts []store.Account
		matches  []store.AddressMatch
	)
	for rows.Next() {
		account, exact, err := scanAddressAccount(rows)
		if err != nil {
			return store.Account{}, err
		}
		accounts = append(accounts, account)
		matches = append(matches, store.AddressMatch{ID: account.ID, Exact: exact})
	}
	if err := rows.Err(); err != nil {
		return store.Account{}, err
	}
	if _, err := store.PickAddressMatch(matches, store.ErrNotFound); err != nil {
		return store.Account{}, err
	}
	return accounts[0], nil
}

// linkedAccount is the account an address was linked to; see pgstore.
func (s *Store) linkedAccount(ctx context.Context, email string) (store.Account, bool, error) {
	var (
		account store.Account
		ok      bool
	)
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		match, found, err := linkedAddress(ctx, tx, email, "")
		if ok = found; !found || err != nil {
			return err
		}
		account, err = scanAccount(tx.QueryRowContext(ctx, "SELECT "+accountColumns+" FROM users WHERE id = ?", match.ID))
		return err
	})
	return account, ok, err
}

func (s *Store) RecordAudit(ctx context.Context, event store.AuditEvent) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO audit_log (user_id, event, method, ip) VALUES (NULLIF(?, 0), ?, NULLIF(?, ''), NULLIF(?, ''))",
		event.UserID, event.Event, event.Method, event.IP)
	return err
}

// scanAddressAccount reads an account row followed by whether its address is
// the exact one asked for.
func scanAddressAccount(rows *sql.Rows) (store.Account, bool, error) {
	var (
		account store.Account
		allowed sql.NullString
		exact   bool
	)
	if err := rows.Scan(&account.ID, &account.Email, &account.PasswordHash, &account.FullName, &account.Role,
		&allowed, &account.Enabled, &account.EmailVerified, &exact); err != nil {
		return store.Account{}, false, err
	}
	var err error
	account.AllowedRoles, err = decodeRoles(allowed)
	return account, exact, err
}
