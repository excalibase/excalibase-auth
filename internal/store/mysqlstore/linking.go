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

func (s *Store) LinkableAccount(ctx context.Context, userID int64) error {
	return linkTarget(s.db.QueryRowContext(ctx, linkTargetQuery, userID))
}

func (s *Store) LinkIdentity(ctx context.Context, userID int64, claim store.IdentityClaim) (store.LinkResult, error) {
	var result store.LinkResult
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		guest, err := linkTargetGuest(tx.QueryRowContext(ctx, linkTargetLockedQuery, userID))
		if err != nil {
			return err
		}
		var owner int64
		err = tx.QueryRowContext(ctx, "SELECT user_id FROM identities WHERE provider = ? AND subject = ? FOR UPDATE",
			claim.Provider, claim.Subject).Scan(&owner)
		switch {
		case err == nil:
			return store.ErrIdentityExists
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		// A guest takes the linked address as its own, so it is claimed like one;
		// an address another account linked stays that account's.
		if guest && claim.Provider != store.EmailProvider {
			if err := addressLinkedElsewhere(ctx, tx, userID, claim.Email); err != nil {
				return err
			}
		}
		if claim.Provider == store.EmailProvider || guest {
			if result.Deleted, err = claimAddress(ctx, tx, userID, claim.Email); err != nil {
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
		if err != nil || !guest {
			return err
		}
		result.Upgraded = true
		return upgradeGuest(ctx, tx, userID, claim.Email)
	})
	if err != nil {
		return store.LinkResult{}, err
	}
	return result, nil
}

// upgradeGuest gives a guest its proven address; see pgstore. allowed_roles
// is assigned before role, which MySQL updates left to right.
func upgradeGuest(ctx context.Context, tx *sql.Tx, userID int64, email string) error {
	_, err := tx.ExecContext(ctx,
		`UPDATE users SET email = ?, email_verified = TRUE, email_verified_at = NOW(6), is_guest = FALSE,
		        allowed_roles = IF(role = ?, NULL, allowed_roles),
		        role = IF(role = ?, 'user', role), updated_at = NOW(6)
		 WHERE id = ? AND is_guest`, email, store.GuestRole, store.GuestRole, userID)
	return err
}

const (
	linkTargetQuery       = "SELECT email_verified AND email_verified_at IS NOT NULL, enabled, is_guest FROM users WHERE id = ?"
	linkTargetLockedQuery = "SELECT email_verified AND email_verified_at IS NOT NULL, enabled, is_guest FROM users WHERE id = ? FOR UPDATE"
	listIdentitiesQuery   = `SELECT id, provider, COALESCE(email, ''), created_at, last_sign_in_at FROM identities
		WHERE user_id = ? ORDER BY id`
	listIdentitiesLockedQuery = `SELECT id, provider, COALESCE(email, ''), created_at, last_sign_in_at FROM identities
		WHERE user_id = ? ORDER BY id FOR UPDATE`
)

// linkTarget reads whether the account may take a link; see pgstore.
func linkTarget(row *sql.Row) error {
	_, err := linkTargetGuest(row)
	return err
}

// linkTargetGuest is linkTarget that also says whether the account is a guest.
func linkTargetGuest(row *sql.Row) (bool, error) {
	var proven, enabled, guest bool
	err := row.Scan(&proven, &enabled, &guest)
	switch {
	case err != nil:
		return false, notFound(err)
	case !enabled:
		return false, store.ErrAccountDisabled
	case !proven && !guest:
		return false, store.ErrAddressUnproven
	}
	return guest, nil
}

// claimAddress refuses an address held by the account, a proven or a
// disabled account, and deletes the unproven ones; see pgstore.
func claimAddress(ctx context.Context, tx *sql.Tx, userID int64, email string) ([]int64, error) {
	squatters, err := addressHolders(ctx, tx, userID, email)
	if err != nil {
		return nil, err
	}
	for _, id := range squatters {
		if _, err := tx.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id); err != nil {
			return nil, err
		}
	}
	return squatters, nil
}

// addressHolders are the unproven accounts answering to the address; any
// other holder is ErrIdentityExists.
func addressHolders(ctx context.Context, tx *sql.Tx, userID int64, email string) ([]int64, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT id, (email_verified AND email_verified_at IS NOT NULL) OR NOT enabled FROM users
		 WHERE LOWER(email) = LOWER(?) FOR UPDATE`, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var squatters []int64
	for rows.Next() {
		var (
			id   int64
			held bool
		)
		if err := rows.Scan(&id, &held); err != nil {
			return nil, err
		}
		if id == userID || held {
			return nil, store.ErrIdentityExists
		}
		squatters = append(squatters, id)
	}
	return squatters, rows.Err()
}

func (s *Store) ListIdentities(ctx context.Context, userID int64) ([]store.Identity, error) {
	return listIdentities(ctx, s.db, userID, false)
}

func listIdentities(ctx context.Context, db querier, userID int64, forUpdate bool) ([]store.Identity, error) {
	query := listIdentitiesQuery
	if forUpdate {
		query = listIdentitiesLockedQuery
	}
	rows, err := db.QueryContext(ctx, query, userID)
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
		if err := tx.QueryRowContext(ctx, "SELECT password IS NOT NULL AND password NOT LIKE '!%' FROM users WHERE id = ? FOR UPDATE",
			userID).Scan(&hasPassword); err != nil {
			return notFound(err)
		}
		identities, err := listIdentities(ctx, tx, userID, true)
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

func addressLinkedElsewhere(ctx context.Context, tx *sql.Tx, userID int64, email string) error {
	var owner int64
	err := tx.QueryRowContext(ctx, "SELECT user_id FROM identities WHERE provider = ? AND subject = ? FOR UPDATE",
		store.EmailProvider, store.AddressKey(email)).Scan(&owner)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return err
	case owner != userID:
		return store.ErrIdentityExists
	}
	return nil
}
