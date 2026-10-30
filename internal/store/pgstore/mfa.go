package pgstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/excalibase/auth/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const factorColumns = "id::text, user_id, factor_type, friendly_name, status, created_at, updated_at"

func scanFactor(row pgx.Row, extra ...any) (store.Factor, error) {
	var factor store.Factor
	fields := append([]any{&factor.ID, &factor.UserID, &factor.FactorType, &factor.FriendlyName, &factor.Status,
		&factor.CreatedAt, &factor.UpdatedAt}, extra...)
	return factor, row.Scan(fields...)
}

// validUUID keeps a malformed id from reaching a uuid column, where it would
// be an error rather than no row.
func validUUID(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil
}

func (s *Store) CreateFactor(ctx context.Context, factor store.NewFactor, limits store.MFALimits) (store.Factor, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return store.Factor{}, fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)
	// The account row serialises enrolments, so the cap holds under concurrency.
	if err := lockAccount(ctx, tx, factor.UserID); err != nil {
		return store.Factor{}, err
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM auth.mfa_factors WHERE user_id = $1 AND status = 'unverified'
		 AND created_at < NOW() - make_interval(secs => $2)`, factor.UserID, limits.StaleUnverified.Seconds()); err != nil {
		return store.Factor{}, err
	}
	var count int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM auth.mfa_factors WHERE user_id = $1", factor.UserID).Scan(&count); err != nil {
		return store.Factor{}, err
	}
	if count >= limits.MaxFactors {
		return store.Factor{}, store.ErrTooManyFactors
	}
	created, err := scanFactor(tx.QueryRow(ctx,
		`INSERT INTO auth.mfa_factors (id, user_id, friendly_name, secret_enc) VALUES ($1, $2, $3, $4)
		 RETURNING `+factorColumns, factor.ID, factor.UserID, factor.FriendlyName, factor.SecretSealed))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return store.Factor{}, store.ErrFactorNameTaken
		}
		return store.Factor{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.Factor{}, err
	}
	return created, nil
}

func (s *Store) ListFactors(ctx context.Context, userID int64) (store.FactorListing, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+factorColumns+" FROM auth.mfa_factors WHERE user_id = $1 ORDER BY created_at, id", userID)
	if err != nil {
		return store.FactorListing{}, err
	}
	factors, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (store.Factor, error) { return scanFactor(row) })
	if err != nil {
		return store.FactorListing{}, err
	}
	listing := store.FactorListing{Factors: factors}
	err = s.pool.QueryRow(ctx, "SELECT count(*) FROM auth.mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL",
		userID).Scan(&listing.RecoveryCodesRemaining)
	return listing, err
}

func (s *Store) HasVerifiedFactor(ctx context.Context, userID int64) (bool, error) {
	var verified bool
	err := s.pool.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM auth.mfa_factors WHERE user_id = $1 AND status = 'verified')", userID).Scan(&verified)
	return verified, err
}

func (s *Store) CreateChallenge(ctx context.Context, userID int64, factorID, challengeID, ip string, expiresAt time.Time) error {
	if !validUUID(factorID) {
		return store.ErrNotFound
	}
	if _, err := s.pool.Exec(ctx, "DELETE FROM auth.mfa_challenges WHERE factor_id = $1 AND expires_at < NOW()", factorID); err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO auth.mfa_challenges (id, factor_id, ip, expires_at)
		 SELECT $1, id, $4, $5 FROM auth.mfa_factors WHERE id = $2 AND user_id = $3`,
		challengeID, factorID, userID, ip, expiresAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) VerifyFactor(ctx context.Context, attempt store.FactorAttempt, limits store.MFALimits, check store.FactorCheck) (store.VerifiedFactor, error) {
	if !validUUID(attempt.FactorID) {
		return store.VerifiedFactor{}, store.ErrNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return store.VerifiedFactor{}, fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)
	// The account is locked first, like every MFA write, so locks never cross.
	if err := lockAccount(ctx, tx, attempt.UserID); err != nil {
		return store.VerifiedFactor{}, err
	}
	secret, err := lockFactor(ctx, tx, attempt, limits)
	if err != nil {
		return store.VerifiedFactor{}, err
	}
	if err := s.liveChallenge(ctx, tx, attempt); err != nil {
		return store.VerifiedFactor{}, err
	}
	if err := failureBudget(ctx, tx, attempt.UserID, &attempt.FactorID, limits); err != nil {
		return store.VerifiedFactor{}, err
	}
	step, ok, err := check(secret)
	if err != nil {
		return store.VerifiedFactor{}, err
	}
	if !ok {
		return store.VerifiedFactor{}, recordFailure(ctx, tx, attempt.UserID, &attempt.FactorID)
	}
	return acceptFactor(ctx, tx, attempt, secret.Factor, step)
}

func lockAccount(ctx context.Context, tx pgx.Tx, userID int64) error {
	var locked int64
	return notFound(tx.QueryRow(ctx, "SELECT id FROM auth.users WHERE id = $1 FOR UPDATE", userID).Scan(&locked))
}

// lockFactor reads the factor under its lock. A stale unverified factor is
// gone; an unverified one of an account that has a verified one takes an aal2
// caller, so a factor planted before MFA was on cannot lift a password to aal2.
func lockFactor(ctx context.Context, tx pgx.Tx, attempt store.FactorAttempt, limits store.MFALimits) (store.FactorSecret, error) {
	var (
		secret         store.FactorSecret
		lastStep       *int64
		stale          bool
		othersVerified bool
	)
	factor, err := scanFactor(tx.QueryRow(ctx,
		`SELECT `+factorColumns+`, secret_enc, last_used_step,
		        status = 'unverified' AND created_at < NOW() - make_interval(secs => $3),
		        EXISTS (SELECT 1 FROM auth.mfa_factors o WHERE o.user_id = $2 AND o.status = 'verified' AND o.id <> $1)
		 FROM auth.mfa_factors WHERE id = $1 AND user_id = $2 FOR UPDATE`,
		attempt.FactorID, attempt.UserID, limits.StaleUnverified.Seconds()), &secret.SecretSealed, &lastStep, &stale, &othersVerified)
	switch {
	case err != nil:
		return secret, notFound(err)
	case stale:
		return secret, store.ErrNotFound
	case factor.Status != store.FactorVerified && othersVerified && !attempt.CallerAAL2:
		return secret, store.ErrInsufficientAAL
	}
	secret.Factor = factor
	if lastStep != nil {
		secret.LastUsedStep = *lastStep
	}
	return secret, nil
}

func (s *Store) liveChallenge(ctx context.Context, tx pgx.Tx, attempt store.FactorAttempt) error {
	if !validUUID(attempt.ChallengeID) {
		return store.ErrInvalidChallenge
	}
	var live bool
	if err := tx.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM auth.mfa_challenges WHERE id = $1 AND factor_id = $2 AND expires_at > NOW())",
		attempt.ChallengeID, attempt.FactorID).Scan(&live); err != nil {
		return err
	}
	if !live {
		return store.ErrInvalidChallenge
	}
	return nil
}

// failureBudget refuses once the window holds MaxFailures wrong codes for the
// factor, or for the account's recovery codes when factorID is nil, or the
// account's day holds MaxDailyFailures across all of them.
func failureBudget(ctx context.Context, tx pgx.Tx, userID int64, factorID *string, limits store.MFALimits) error {
	var recent, today int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE factor_id IS NOT DISTINCT FROM $2::uuid AND failed_at > NOW() - make_interval(secs => $3)),
		        count(*)
		 FROM auth.mfa_failures WHERE user_id = $1 AND failed_at > NOW() - INTERVAL '1 day'`,
		userID, factorID, limits.FailureWindow.Seconds()).Scan(&recent, &today); err != nil {
		return err
	}
	if recent >= limits.MaxFailures || today >= limits.MaxDailyFailures {
		return store.ErrTooManyAttempts
	}
	return nil
}

// recordFailure commits the wrong code's row and answers ErrInvalidCode.
func recordFailure(ctx context.Context, tx pgx.Tx, userID int64, factorID *string) error {
	if _, err := tx.Exec(ctx, "DELETE FROM auth.mfa_failures WHERE user_id = $1 AND failed_at < NOW() - INTERVAL '1 day'", userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO auth.mfa_failures (user_id, factor_id) VALUES ($1, $2::uuid)", userID, factorID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return store.ErrInvalidCode
}

// acceptFactor spends the step and the challenge; the account's first
// verified factor also ends its other unverified ones.
func acceptFactor(ctx context.Context, tx pgx.Tx, attempt store.FactorAttempt, factor store.Factor, step int64) (store.VerifiedFactor, error) {
	var othersVerified bool
	if err := tx.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM auth.mfa_factors WHERE user_id = $1 AND status = 'verified' AND id <> $2)",
		attempt.UserID, attempt.FactorID).Scan(&othersVerified); err != nil {
		return store.VerifiedFactor{}, err
	}
	updated, err := scanFactor(tx.QueryRow(ctx,
		`UPDATE auth.mfa_factors SET status = 'verified', last_used_step = $2, updated_at = NOW()
		 WHERE id = $1 RETURNING `+factorColumns, attempt.FactorID, step))
	if err != nil {
		return store.VerifiedFactor{}, err
	}
	if _, err := tx.Exec(ctx, "DELETE FROM auth.mfa_challenges WHERE factor_id = $1 AND (id = $2 OR expires_at < NOW())",
		attempt.FactorID, attempt.ChallengeID); err != nil {
		return store.VerifiedFactor{}, err
	}
	first := factor.Status != store.FactorVerified && !othersVerified
	if first {
		if _, err := tx.Exec(ctx, "DELETE FROM auth.mfa_factors WHERE user_id = $1 AND status = 'unverified'", attempt.UserID); err != nil {
			return store.VerifiedFactor{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return store.VerifiedFactor{}, err
	}
	return store.VerifiedFactor{Factor: updated, FirstForAccount: first}, nil
}

func (s *Store) DeleteFactor(ctx context.Context, userID int64, factorID string) error {
	if !validUUID(factorID) {
		return store.ErrNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)
	if err := lockAccount(ctx, tx, userID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, "DELETE FROM auth.mfa_factors WHERE id = $1 AND user_id = $2", factorID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM auth.mfa_recovery_codes WHERE user_id = $1
		 AND NOT EXISTS (SELECT 1 FROM auth.mfa_factors WHERE user_id = $1 AND status = 'verified')`, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID int64, hashes []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)
	if err := lockAccount(ctx, tx, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "DELETE FROM auth.mfa_recovery_codes WHERE user_id = $1", userID); err != nil {
		return err
	}
	for _, hash := range hashes {
		if _, err := tx.Exec(ctx, "INSERT INTO auth.mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)", userID, hash); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) RedeemRecoveryCode(ctx context.Context, userID int64, hash string, limits store.MFALimits) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)
	if err := lockAccount(ctx, tx, userID); err != nil {
		return err
	}
	if err := failureBudget(ctx, tx, userID, nil, limits); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`UPDATE auth.mfa_recovery_codes SET used_at = NOW()
		 WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
		 AND EXISTS (SELECT 1 FROM auth.mfa_factors WHERE user_id = $1 AND status = 'verified')`, userID, hash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return recordFailure(ctx, tx, userID, nil)
	}
	return tx.Commit(ctx)
}

func (s *Store) ResetMFA(ctx context.Context, userID int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)
	if err := lockAccount(ctx, tx, userID); err != nil {
		return err
	}
	for _, statement := range []string{
		"DELETE FROM auth.mfa_factors WHERE user_id = $1",
		"DELETE FROM auth.mfa_recovery_codes WHERE user_id = $1",
		"DELETE FROM auth.mfa_failures WHERE user_id = $1",
		"UPDATE auth.refresh_tokens SET revoked = true WHERE user_id = $1 AND revoked = false",
	} {
		if _, err := tx.Exec(ctx, statement, userID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
