package mysqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/excalibase/auth/internal/store"
	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
)

const factorColumns = "id, user_id, factor_type, friendly_name, status, created_at, updated_at"

// lockFactorQuery reads a factor under its lock, with whether it is stale and
// whether the account has another verified factor; its first columns are factorColumns.
const lockFactorQuery = `SELECT id, user_id, factor_type, friendly_name, status, created_at, updated_at, secret_enc, last_used_step,
        status = 'unverified' AND created_at < NOW(6) - INTERVAL ? MICROSECOND,
        EXISTS (SELECT 1 FROM mfa_factors o WHERE o.user_id = ? AND o.status = 'verified' AND o.id <> ?)
 FROM mfa_factors WHERE id = ? AND user_id = ? FOR UPDATE`

func scanFactor(row rowScanner, extra ...any) (store.Factor, error) {
	var factor store.Factor
	fields := append([]any{&factor.ID, &factor.UserID, &factor.FactorType, &factor.FriendlyName, &factor.Status,
		&factor.CreatedAt, &factor.UpdatedAt}, extra...)
	return factor, row.Scan(fields...)
}

// lockAccount serialises an account's MFA writes on its row.
func lockAccount(ctx context.Context, tx *sql.Tx, userID int64) error {
	var locked int64
	return notFound(tx.QueryRowContext(ctx, "SELECT id FROM users WHERE id = ? FOR UPDATE", userID).Scan(&locked))
}

func (s *Store) CreateFactor(ctx context.Context, factor store.NewFactor, limits store.MFALimits) (store.Factor, error) {
	var created store.Factor
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if err := lockAccount(ctx, tx, factor.UserID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM mfa_factors WHERE user_id = ? AND status = 'unverified'
			 AND created_at < NOW(6) - INTERVAL ? MICROSECOND`, factor.UserID, limits.StaleUnverified.Microseconds()); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM mfa_factors WHERE user_id = ?", factor.UserID).Scan(&count); err != nil {
			return err
		}
		if count >= limits.MaxFactors {
			return store.ErrTooManyFactors
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO mfa_factors (id, user_id, friendly_name, secret_enc) VALUES (?, ?, ?, ?)",
			factor.ID, factor.UserID, factor.FriendlyName, factor.SecretSealed); err != nil {
			var mysqlErr *mysql.MySQLError
			if errors.As(err, &mysqlErr) && mysqlErr.Number == duplicateEntry {
				return store.ErrFactorNameTaken
			}
			return err
		}
		var err error
		created, err = scanFactor(tx.QueryRowContext(ctx, "SELECT "+factorColumns+" FROM mfa_factors WHERE id = ?", factor.ID))
		return err
	})
	return created, err
}

func (s *Store) ListFactors(ctx context.Context, userID int64) (store.FactorListing, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+factorColumns+" FROM mfa_factors WHERE user_id = ? ORDER BY created_at, id", userID)
	if err != nil {
		return store.FactorListing{}, err
	}
	defer rows.Close()
	listing := store.FactorListing{}
	for rows.Next() {
		factor, err := scanFactor(rows)
		if err != nil {
			return store.FactorListing{}, err
		}
		listing.Factors = append(listing.Factors, factor)
	}
	if err := rows.Err(); err != nil {
		return store.FactorListing{}, err
	}
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL",
		userID).Scan(&listing.RecoveryCodesRemaining)
	return listing, err
}

func (s *Store) HasVerifiedFactor(ctx context.Context, userID int64) (bool, error) {
	var verified bool
	err := s.db.QueryRowContext(ctx,
		"SELECT EXISTS (SELECT 1 FROM mfa_factors WHERE user_id = ? AND status = 'verified')", userID).Scan(&verified)
	return verified, err
}

func (s *Store) CreateChallenge(ctx context.Context, userID int64, factorID, challengeID, ip string, expiresAt time.Time) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM mfa_challenges WHERE factor_id = ? AND expires_at < NOW(6)", factorID); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO mfa_challenges (id, factor_id, ip, expires_at)
		 SELECT ?, id, ?, ? FROM mfa_factors WHERE id = ? AND user_id = ?`,
		challengeID, ip, expiresAt.UTC(), factorID, userID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) VerifyFactor(ctx context.Context, attempt store.FactorAttempt, limits store.MFALimits, check store.FactorCheck) (store.VerifiedFactor, error) {
	var verified store.VerifiedFactor
	counted := false
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		// The account is locked first, like every MFA write, so locks never cross.
		if err := lockAccount(ctx, tx, attempt.UserID); err != nil {
			return err
		}
		secret, err := lockFactor(ctx, tx, attempt, limits)
		if err != nil {
			return err
		}
		if err := liveChallenge(ctx, tx, attempt); err != nil {
			return err
		}
		spender := failureSpender{userID: attempt.UserID, familyID: attempt.FamilyID,
			factorID: sql.NullString{String: attempt.FactorID, Valid: true}, callerAAL2: attempt.CallerAAL2}
		if err := failureBudget(ctx, tx, spender, limits); err != nil {
			return err
		}
		step, ok, err := check(secret)
		if err != nil {
			return err
		}
		if !ok {
			counted = true
			return recordFailure(ctx, tx, spender)
		}
		verified, err = acceptFactor(ctx, tx, attempt, secret.Factor, step)
		return err
	})
	if counted && err == nil {
		return store.VerifiedFactor{}, store.ErrInvalidCode
	}
	return verified, err
}

// lockFactor reads the factor under its lock. A stale unverified factor is
// gone; an unverified one of an account that has a verified one takes an aal2
// caller, so a factor planted before MFA was on cannot lift a password to aal2.
func lockFactor(ctx context.Context, tx *sql.Tx, attempt store.FactorAttempt, limits store.MFALimits) (store.FactorSecret, error) {
	var (
		secret         store.FactorSecret
		lastStep       sql.NullInt64
		stale          bool
		othersVerified bool
	)
	factor, err := scanFactor(tx.QueryRowContext(ctx, lockFactorQuery,
		limits.StaleUnverified.Microseconds(), attempt.UserID, attempt.FactorID, attempt.FactorID, attempt.UserID),
		&secret.SecretSealed, &lastStep, &stale, &othersVerified)
	switch {
	case err != nil:
		return secret, notFound(err)
	case stale:
		return secret, store.ErrNotFound
	case factor.Status != store.FactorVerified && othersVerified && !attempt.CallerAAL2:
		return secret, store.ErrInsufficientAAL
	}
	secret.Factor = factor
	secret.LastUsedStep = lastStep.Int64
	return secret, nil
}

func liveChallenge(ctx context.Context, tx *sql.Tx, attempt store.FactorAttempt) error {
	var live bool
	if err := tx.QueryRowContext(ctx,
		"SELECT EXISTS (SELECT 1 FROM mfa_challenges WHERE id = ? AND factor_id = ? AND expires_at > NOW(6))",
		attempt.ChallengeID, attempt.FactorID).Scan(&live); err != nil {
		return err
	}
	if !live {
		return store.ErrInvalidChallenge
	}
	return nil
}

// failureSpender is who a wrong code is counted against: the session, for
// one factor or (factorID not valid) the recovery codes.
type failureSpender struct {
	userID     int64
	familyID   uuid.UUID
	factorID   sql.NullString
	callerAAL2 bool
}

// failureBudget refuses once the session's window holds MaxFailures wrong
// codes for the factor or the recovery codes, its day holds MaxDailyFailures,
// or, for a TOTP code from aal1, the account's day holds MaxAccountDailyFailures.
func failureBudget(ctx context.Context, tx *sql.Tx, spender failureSpender, limits store.MFALimits) error {
	var recent, session, account int
	family := spender.familyID.String()
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(family_id <=> ? AND factor_id <=> ? AND failed_at > NOW(6) - INTERVAL ? MICROSECOND), 0),
		        COALESCE(SUM(family_id <=> ?), 0),
		        COALESCE(SUM(factor_id IS NOT NULL), 0)
		 FROM mfa_failures WHERE user_id = ? AND failed_at > NOW(6) - INTERVAL 1 DAY`,
		family, spender.factorID, limits.FailureWindow.Microseconds(), family, spender.userID).Scan(&recent, &session, &account); err != nil {
		return err
	}
	accountCapped := spender.factorID.Valid && !spender.callerAAL2 && account >= limits.MaxAccountDailyFailures
	if recent >= limits.MaxFailures || session >= limits.MaxDailyFailures || accountCapped {
		return store.ErrTooManyAttempts
	}
	return nil
}

// recordFailure stores the wrong code's row; the caller commits and answers ErrInvalidCode.
func recordFailure(ctx context.Context, tx *sql.Tx, spender failureSpender) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM mfa_failures WHERE user_id = ? AND failed_at < NOW(6) - INTERVAL 1 DAY", spender.userID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO mfa_failures (user_id, factor_id, family_id) VALUES (?, ?, ?)",
		spender.userID, spender.factorID, spender.familyID.String())
	return err
}

// acceptFactor spends the step and the challenge; the account's first
// verified factor also ends its other unverified ones.
func acceptFactor(ctx context.Context, tx *sql.Tx, attempt store.FactorAttempt, factor store.Factor, step int64) (store.VerifiedFactor, error) {
	var othersVerified bool
	if err := tx.QueryRowContext(ctx,
		"SELECT EXISTS (SELECT 1 FROM mfa_factors WHERE user_id = ? AND status = 'verified' AND id <> ?)",
		attempt.UserID, attempt.FactorID).Scan(&othersVerified); err != nil {
		return store.VerifiedFactor{}, err
	}
	if _, err := tx.ExecContext(ctx,
		"UPDATE mfa_factors SET status = 'verified', last_used_step = ?, updated_at = NOW(6) WHERE id = ?",
		step, attempt.FactorID); err != nil {
		return store.VerifiedFactor{}, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM mfa_challenges WHERE factor_id = ? AND (id = ? OR expires_at < NOW(6))",
		attempt.FactorID, attempt.ChallengeID); err != nil {
		return store.VerifiedFactor{}, err
	}
	first := factor.Status != store.FactorVerified && !othersVerified
	if first {
		if _, err := tx.ExecContext(ctx, "DELETE FROM mfa_factors WHERE user_id = ? AND status = 'unverified'", attempt.UserID); err != nil {
			return store.VerifiedFactor{}, err
		}
	}
	updated, err := scanFactor(tx.QueryRowContext(ctx, "SELECT "+factorColumns+" FROM mfa_factors WHERE id = ?", attempt.FactorID))
	if err != nil {
		return store.VerifiedFactor{}, err
	}
	return store.VerifiedFactor{Factor: updated, FirstForAccount: first}, nil
}

func (s *Store) DeleteFactor(ctx context.Context, userID int64, factorID string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if err := lockAccount(ctx, tx, userID); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, "DELETE FROM mfa_factors WHERE id = ? AND user_id = ?", factorID, userID)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if changed == 0 {
			return store.ErrNotFound
		}
		var verifiedLeft bool
		if err := tx.QueryRowContext(ctx,
			"SELECT EXISTS (SELECT 1 FROM mfa_factors WHERE user_id = ? AND status = 'verified')", userID).Scan(&verifiedLeft); err != nil {
			return err
		}
		if verifiedLeft {
			return nil
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM mfa_recovery_codes WHERE user_id = ?", userID)
		return err
	})
}

func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID int64, hashes []string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if err := lockAccount(ctx, tx, userID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM mfa_recovery_codes WHERE user_id = ?", userID); err != nil {
			return err
		}
		for _, hash := range hashes {
			if _, err := tx.ExecContext(ctx, "INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES (?, ?)", userID, hash); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) AddRecoveryCodesIfNone(ctx context.Context, userID int64, hashes []string) (bool, error) {
	added := false
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if err := lockAccount(ctx, tx, userID); err != nil {
			return err
		}
		// A reset or removal racing the step-up leaves no factor; no set may outlive it.
		var unspent, enrolled bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL),
			        EXISTS (SELECT 1 FROM mfa_factors WHERE user_id = ? AND status = 'verified')`, userID, userID).Scan(&unspent, &enrolled); err != nil {
			return err
		}
		if unspent || !enrolled {
			return nil
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM mfa_recovery_codes WHERE user_id = ?", userID); err != nil {
			return err
		}
		for _, hash := range hashes {
			if _, err := tx.ExecContext(ctx, "INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES (?, ?)", userID, hash); err != nil {
				return err
			}
		}
		added = true
		return nil
	})
	return added && err == nil, err
}

func (s *Store) RedeemRecoveryCode(ctx context.Context, userID int64, familyID uuid.UUID, hash string, limits store.MFALimits) error {
	counted := false
	spender := failureSpender{userID: userID, familyID: familyID}
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if err := lockAccount(ctx, tx, userID); err != nil {
			return err
		}
		if err := failureBudget(ctx, tx, spender, limits); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx,
			`UPDATE mfa_recovery_codes SET used_at = NOW(6)
			 WHERE user_id = ? AND code_hash = ? AND used_at IS NULL
			 AND EXISTS (SELECT 1 FROM mfa_factors WHERE user_id = ? AND status = 'verified')`, userID, hash, userID)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if changed == 0 {
			counted = true
			return recordFailure(ctx, tx, spender)
		}
		return nil
	})
	if counted && err == nil {
		return store.ErrInvalidCode
	}
	return err
}

func (s *Store) ResetMFA(ctx context.Context, userID int64) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if err := lockAccount(ctx, tx, userID); err != nil {
			return err
		}
		for _, statement := range []string{
			"DELETE FROM mfa_factors WHERE user_id = ?",
			"DELETE FROM mfa_recovery_codes WHERE user_id = ?",
			"DELETE FROM mfa_failures WHERE user_id = ?",
			"UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = ? AND revoked = FALSE",
		} {
			if _, err := tx.ExecContext(ctx, statement, userID); err != nil {
				return err
			}
		}
		return nil
	})
}
