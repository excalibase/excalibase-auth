package mysqlstore

import (
	"context"
	"database/sql"
	"errors"
	"slices"

	"github.com/excalibase/auth/internal/store"
	"github.com/go-sql-driver/mysql"
)

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func (s *Store) LinkIdentity(ctx context.Context, userID int64, claim store.IdentityClaim) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if err := lockLinkTarget(ctx, tx, userID); err != nil {
			return err
		}
		var owner int64
		err := tx.QueryRowContext(ctx, "SELECT user_id FROM identities WHERE provider = ? AND subject = ? FOR UPDATE",
			claim.Provider, claim.Subject).Scan(&owner)
		switch {
		case err == nil:
			return store.ErrIdentityExists
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		if claim.Provider == store.EmailProvider {
			if err := claimAddress(ctx, tx, userID, claim.Email); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO identities (user_id, provider, subject, email, email_verified) VALUES (?, ?, ?, ?, TRUE)`,
			userID, claim.Provider, claim.Subject, claim.Email)
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == duplicateEntry {
			return store.ErrIdentityExists
		}
		return err
	})
}

// lockLinkTarget holds the account for the link; see pgstore.
func lockLinkTarget(ctx context.Context, tx *sql.Tx, userID int64) error {
	var proven, enabled bool
	err := tx.QueryRowContext(ctx,
		"SELECT email_verified AND email_verified_at IS NOT NULL, enabled FROM users WHERE id = ? FOR UPDATE",
		userID).Scan(&proven, &enabled)
	switch {
	case err != nil:
		return notFound(err)
	case !enabled:
		return store.ErrAccountDisabled
	case !proven:
		return store.ErrAddressUnproven
	}
	return nil
}

// claimAddress refuses an address held by the account, a proven or a
// disabled account, and deletes the unproven ones; see pgstore.
func claimAddress(ctx context.Context, tx *sql.Tx, userID int64, email string) error {
	rows, err := tx.QueryContext(ctx,
		`SELECT id, (email_verified AND email_verified_at IS NOT NULL) OR NOT enabled FROM users
		 WHERE LOWER(email) = LOWER(?) FOR UPDATE`, email)
	if err != nil {
		return err
	}
	defer rows.Close()
	var squatters []int64
	for rows.Next() {
		var (
			id   int64
			held bool
		)
		if err := rows.Scan(&id, &held); err != nil {
			return err
		}
		if id == userID || held {
			return store.ErrIdentityExists
		}
		squatters = append(squatters, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range squatters {
		if _, err := tx.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ListIdentities(ctx context.Context, userID int64) ([]store.Identity, error) {
	return listIdentities(ctx, s.db, userID, "")
}

func listIdentities(ctx context.Context, db querier, userID int64, lock string) ([]store.Identity, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, provider, COALESCE(email, ''), created_at, last_sign_in_at FROM identities
		 WHERE user_id = ? ORDER BY id`+lock, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	identities := []store.Identity{}
	for rows.Next() {
		var (
			identity store.Identity
			signedIn sql.NullTime
		)
		if err := rows.Scan(&identity.ID, &identity.Provider, &identity.Email, &identity.CreatedAt, &signedIn); err != nil {
			return nil, err
		}
		if signedIn.Valid {
			identity.LastSignInAt = &signedIn.Time
		}
		identities = append(identities, identity)
	}
	return identities, rows.Err()
}

func (s *Store) UnlinkIdentity(ctx context.Context, userID, identityID int64) (store.Identity, error) {
	var removed store.Identity
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var hasPassword bool
		if err := tx.QueryRowContext(ctx, "SELECT password IS NOT NULL FROM users WHERE id = ? FOR UPDATE",
			userID).Scan(&hasPassword); err != nil {
			return notFound(err)
		}
		identities, err := listIdentities(ctx, tx, userID, " FOR UPDATE")
		if err != nil {
			return err
		}
		at := slices.IndexFunc(identities, func(identity store.Identity) bool { return identity.ID == identityID })
		switch {
		case at < 0:
			return store.ErrNotFound
		case len(identities) == 1 && !hasPassword:
			return store.ErrLastSignInMethod
		}
		removed = identities[at]
		_, err = tx.ExecContext(ctx, "DELETE FROM identities WHERE id = ? AND user_id = ?", identityID, userID)
		return err
	})
	return removed, err
}
