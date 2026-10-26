package pgstore

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/excalibase/auth/internal/store"
	"github.com/jackc/pgx/v5"
)

func (s *Store) SaveEmailOTP(ctx context.Context, otp store.EmailOTP, limits store.OTPLimits) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		"INSERT INTO auth.email_otp_lock (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET id = EXCLUDED.id"); err != nil {
		return false, err
	}
	mailed, err := withinOTPLimits(ctx, tx, otp, limits)
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, "DELETE FROM auth.email_otps WHERE created_at < NOW() - INTERVAL '1 day'"); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE auth.email_otps SET consumed_at = NOW()
		 WHERE $3 AND lower(email) = lower($1) AND code_challenge = $2 AND consumed_at IS NULL`, otp.Email, otp.CodeChallenge, mailed); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO auth.email_otps (email, kind, link_hash, code_hmac, code_challenge, create_user, mailed, ip, expires_at, link_user_id)
		 VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), $5, $6, $7, NULLIF($8, ''), $9, NULLIF($10, 0))`,
		otp.Email, otp.Kind, otp.LinkHash, otp.CodeHMAC, otp.CodeChallenge, otp.CreateUser, mailed, otp.IP, otp.ExpiresAt, otp.LinkUserID); err != nil {
		return false, err
	}
	return mailed, tx.Commit(ctx)
}

// withinOTPLimits counts the sends the budgets allow, under the lock row, and
// says whether this one may be mailed.
func withinOTPLimits(ctx context.Context, tx pgx.Tx, otp store.EmailOTP, limits store.OTPLimits) (bool, error) {
	var recent, lastHour, fromIP, mailedToday int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE lower(email) = lower($1) AND created_at > NOW() - make_interval(secs => $2)),
		        count(*) FILTER (WHERE lower(email) = lower($1) AND created_at > NOW() - INTERVAL '1 hour'),
		        count(*) FILTER (WHERE ip = $3),
		        count(*) FILTER (WHERE mailed)
		 FROM auth.email_otps WHERE created_at > NOW() - INTERVAL '1 day'`,
		otp.Email, limits.MinInterval.Seconds(), otp.IP).Scan(&recent, &lastHour, &fromIP, &mailedToday); err != nil {
		return false, err
	}
	if recent > 0 || lastHour >= limits.PerAddressHour || fromIP >= limits.PerIPDay {
		return false, store.ErrRateLimited
	}
	return otp.Mailed && mailedToday < limits.PerProjectDay, nil
}

const liveOTPColumns = `SELECT id, email, kind, COALESCE(link_hash, ''), COALESCE(code_hmac, ''), code_challenge, create_user, attempts, expires_at,
	COALESCE(link_user_id, 0)
	FROM auth.email_otps WHERE mailed AND consumed_at IS NULL AND expires_at > NOW() AND `

const (
	liveLinkQuery = liveOTPColumns + "link_hash = $1 AND kind = $2 FOR UPDATE"
	liveCodeQuery = liveOTPColumns + `lower(email) = lower($1) AND kind = $2 AND attempts < $3
		AND code_challenge = $4 ORDER BY created_at DESC, id DESC LIMIT 1 FOR UPDATE`
)

func (s *Store) RedeemEmailOTP(ctx context.Context, lookup store.OTPLookup, limits store.OTPAttempts, check func(store.EmailOTP) bool) (store.EmailOTP, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return store.EmailOTP{}, fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)

	var (
		id  int64
		otp store.EmailOTP
	)
	var row pgx.Row
	if lookup.LinkHash != "" {
		row = tx.QueryRow(ctx, liveLinkQuery, lookup.LinkHash, store.OTPMagicLink)
	} else {
		row = tx.QueryRow(ctx, liveCodeQuery, lookup.Email, store.OTPEmailCode, limits.PerCode, lookup.CodeChallenge)
	}
	if err := row.Scan(&id, &otp.Email, &otp.Kind, &otp.LinkHash, &otp.CodeHMAC, &otp.CodeChallenge,
		&otp.CreateUser, &otp.Attempts, &otp.ExpiresAt, &otp.LinkUserID); err != nil {
		return store.EmailOTP{}, notFound(err)
	}
	accepted := check(otp)
	spent := accepted || otp.Kind == store.OTPMagicLink || otp.Attempts+1 >= limits.PerCode
	attempts := otp.Attempts
	if !accepted {
		attempts++
	}
	if _, err := tx.Exec(ctx,
		"UPDATE auth.email_otps SET attempts = $2, consumed_at = CASE WHEN $3 THEN NOW() END WHERE id = $1",
		id, attempts, spent); err != nil {
		return store.EmailOTP{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.EmailOTP{}, err
	}
	if !accepted {
		return store.EmailOTP{}, store.ErrNotFound
	}
	return otp, nil
}

func (s *Store) SignInWithEmail(ctx context.Context, email, fullName string, allowCreate bool) (store.Account, store.IdentityOutcome, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return store.Account{}, 0, fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)

	claim := store.IdentityClaim{Email: email, FullName: fullName}
	userID, verified, err := accountForAddress(ctx, tx, email)
	outcome := store.IdentityKnown
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if !allowCreate {
			return store.Account{}, 0, store.ErrSignupsDisabled
		}
		userID, err = createProviderUser(ctx, tx, claim)
		outcome = store.IdentityCreated
	case err != nil:
		return store.Account{}, 0, err
	case !verified:
		userID, err = takeOver(ctx, tx, userID, claim)
		outcome = store.IdentityTookOver
	}
	if err != nil {
		return store.Account{}, 0, err
	}
	account, err := scanAccount(tx.QueryRow(ctx, "SELECT "+accountColumns+" FROM auth.users WHERE id = $1", userID))
	if err != nil {
		return store.Account{}, 0, err
	}
	return account, outcome, tx.Commit(ctx)
}

func (s *Store) AccountByAddress(ctx context.Context, email string) (store.Account, error) {
	linked, err := scanAccount(s.pool.QueryRow(ctx, "SELECT "+accountColumns+` FROM auth.users
		WHERE id = (SELECT user_id FROM auth.identities WHERE provider = $1 AND subject = $2)`,
		store.EmailProvider, strings.ToLower(email)))
	if !errors.Is(err, store.ErrNotFound) {
		return linked, err
	}
	rows, err := s.pool.Query(ctx, "SELECT "+accountColumns+`, email = $1 FROM auth.users
		WHERE lower(email) = lower($1) ORDER BY email = $1 DESC, id LIMIT 2`, email)
	if err != nil {
		return store.Account{}, err
	}
	defer rows.Close()
	var (
		accounts []store.Account
		matches  []store.AddressMatch
	)
	for rows.Next() {
		var account store.Account
		var exact bool
		if err := rows.Scan(&account.ID, &account.Email, &account.PasswordHash, &account.FullName, &account.Role,
			&account.AllowedRoles, &account.Enabled, &account.EmailVerified, &exact); err != nil {
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

func (s *Store) RecordAudit(ctx context.Context, event store.AuditEvent) error {
	_, err := s.pool.Exec(ctx,
		"INSERT INTO auth.audit_log (user_id, event, method, ip) VALUES (NULLIF($1, 0), $2, NULLIF($3, ''), NULLIF($4, ''))",
		event.UserID, event.Event, event.Method, event.IP)
	return err
}
