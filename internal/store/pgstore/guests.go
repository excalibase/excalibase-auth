package pgstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/excalibase/auth/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// guestPage bounds how many candidates one cleanup query reads.
const guestPage = 200

func (s *Store) CreateGuest(ctx context.Context, client string, limits store.GuestLimits) (store.Account, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return store.Account{}, fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)

	// A missing lock row would leave the counts unserialised, so it is an error.
	var locked int
	if err := tx.QueryRow(ctx, "SELECT id FROM auth.guest_lock WHERE id = 1 FOR UPDATE").Scan(&locked); err != nil {
		return store.Account{}, err
	}
	var fromClient, today int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE ip = $1 AND created_at > NOW() - INTERVAL '1 hour'), count(*)
		 FROM auth.guest_sign_ups WHERE created_at > NOW() - INTERVAL '1 day'`, client).Scan(&fromClient, &today); err != nil {
		return store.Account{}, err
	}
	if fromClient >= limits.PerClientHour || today >= limits.PerProjectDay {
		return store.Account{}, store.ErrRateLimited
	}
	if _, err := tx.Exec(ctx, "DELETE FROM auth.guest_sign_ups WHERE created_at < NOW() - INTERVAL '1 day'"); err != nil {
		return store.Account{}, err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO auth.guest_sign_ups (ip) VALUES ($1)", client); err != nil {
		return store.Account{}, err
	}
	account, err := scanAccount(tx.QueryRow(ctx,
		`INSERT INTO auth.users (email, password, full_name, role, enabled, email_verified, is_guest, created_at, updated_at, last_login_at)
		 VALUES (NULL, NULL, '', $1, true, false, true, NOW(), NOW(), NOW()) RETURNING `+accountColumns, store.GuestRole))
	if err != nil {
		return store.Account{}, err
	}
	return account, tx.Commit(ctx)
}

func (s *Store) ClaimGuestCleanup(ctx context.Context, every time.Duration) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE auth.guest_lock SET cleaned_at = NOW()
		 WHERE id = 1 AND (cleaned_at IS NULL OR cleaned_at <= NOW() - make_interval(secs => $1))`, every.Seconds())
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// inactiveGuestsQuery lists guests that neither signed in nor refreshed since $1.
const inactiveGuestsQuery = `SELECT u.id FROM auth.users u
	WHERE u.is_guest AND u.id > $2 AND u.created_at < $1 AND COALESCE(u.last_login_at, u.created_at) < $1
	  AND NOT EXISTS (SELECT 1 FROM auth.refresh_tokens r WHERE r.user_id = u.id AND r.created_at >= $1)
	ORDER BY u.id LIMIT $3`

func (s *Store) DeleteInactiveGuests(ctx context.Context, cutoff time.Time, limit int) (int, error) {
	deleted, after := 0, int64(0)
	for deleted < limit {
		rows, err := s.pool.Query(ctx, inactiveGuestsQuery, cutoff, after, guestPage)
		if err != nil {
			return deleted, err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil || len(ids) == 0 {
			return deleted, err
		}
		for _, id := range ids {
			after = id
			removed, err := s.deleteInactiveGuest(ctx, id, cutoff)
			if err != nil {
				return deleted, err
			}
			if removed {
				deleted++
			}
			if deleted >= limit {
				break
			}
		}
	}
	return deleted, nil
}

// deleteInactiveGuest re-checks the guest is still idle as it deletes it; one
// an app table references stays.
func (s *Store) deleteInactiveGuest(ctx context.Context, id int64, cutoff time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM auth.users u WHERE u.id = $1 AND u.is_guest AND COALESCE(u.last_login_at, u.created_at) < $2
		   AND NOT EXISTS (SELECT 1 FROM auth.refresh_tokens r WHERE r.user_id = u.id AND r.created_at >= $2)`, id, cutoff)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == foreignKeyViolation {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
