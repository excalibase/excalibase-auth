package mysqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/excalibase/auth/internal/store"
)

// guestPage bounds how many candidates one cleanup query reads.
const guestPage = 200

func (s *Store) CreateGuest(ctx context.Context, client string, limits store.GuestLimits) (store.Account, error) {
	var account store.Account
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var locked int
		if err := tx.QueryRowContext(ctx, "SELECT id FROM guest_lock WHERE id = 1 FOR UPDATE").Scan(&locked); err != nil {
			return err
		}
		var fromClient, today int
		if err := tx.QueryRowContext(ctx,
			`SELECT COALESCE(SUM(ip = ? AND created_at > NOW(6) - INTERVAL 1 HOUR), 0), COUNT(*)
			 FROM guest_sign_ups WHERE created_at > NOW(6) - INTERVAL 1 DAY`, client).Scan(&fromClient, &today); err != nil {
			return err
		}
		if fromClient >= limits.PerClientHour || today >= limits.PerProjectDay {
			return store.ErrRateLimited
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM guest_sign_ups WHERE created_at < NOW(6) - INTERVAL 1 DAY"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO guest_sign_ups (ip) VALUES (?)", client); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx,
			`INSERT INTO users (email, password, full_name, role, enabled, email_verified, is_guest, created_at, updated_at, last_login_at)
			 VALUES (NULL, NULL, '', ?, TRUE, FALSE, TRUE, NOW(6), NOW(6), NOW(6))`, store.GuestRole)
		if err != nil {
			return err
		}
		id, err := result.LastInsertId()
		if err != nil {
			return err
		}
		account, err = scanAccount(tx.QueryRowContext(ctx, "SELECT "+accountColumns+" FROM users WHERE id = ?", id))
		return err
	})
	if err != nil {
		return store.Account{}, err
	}
	return account, nil
}

func (s *Store) ClaimGuestCleanup(ctx context.Context, every time.Duration) (bool, error) {
	result, err := s.db.ExecContext(ctx,
		`UPDATE guest_lock SET cleaned_at = NOW(6)
		 WHERE id = 1 AND (cleaned_at IS NULL OR cleaned_at <= NOW(6) - INTERVAL ? MICROSECOND)`, every.Microseconds())
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}

// inactiveGuestsQuery lists guests that neither signed in nor refreshed since the cutoff.
const inactiveGuestsQuery = `SELECT u.id FROM users u
	WHERE u.is_guest AND u.id > ? AND u.created_at < ? AND COALESCE(u.last_login_at, u.created_at) < ?
	  AND NOT EXISTS (SELECT 1 FROM refresh_tokens r WHERE r.user_id = u.id AND r.created_at >= ?)
	ORDER BY u.id LIMIT ?`

func (s *Store) DeleteInactiveGuests(ctx context.Context, cutoff time.Time, limit int) (int, error) {
	cutoff = cutoff.UTC()
	deleted, after := 0, int64(0)
	for deleted < limit {
		ids, err := s.inactiveGuests(ctx, cutoff, after)
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

func (s *Store) inactiveGuests(ctx context.Context, cutoff time.Time, after int64) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, inactiveGuestsQuery, after, cutoff, cutoff, cutoff, guestPage)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// deleteInactiveGuest re-checks the guest is still idle as it deletes it; one
// an app table references stays.
func (s *Store) deleteInactiveGuest(ctx context.Context, id int64, cutoff time.Time) (bool, error) {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM users WHERE id = ? AND is_guest AND COALESCE(last_login_at, created_at) < ?
		   AND NOT EXISTS (SELECT 1 FROM refresh_tokens r WHERE r.user_id = ? AND r.created_at >= ?)`, id, cutoff, id, cutoff)
	if errors.Is(referenced(err), store.ErrUserReferenced) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}
