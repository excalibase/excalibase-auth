package pgstore

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/excalibase/auth/internal/store"
	"github.com/jackc/pgx/v5"
)

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func (s *Store) LinkableAccount(ctx context.Context, userID int64) error {
	return linkTarget(ctx, s.pool.QueryRow(ctx, linkTargetQuery, userID))
}

func (s *Store) LinkIdentity(ctx context.Context, userID int64, claim store.IdentityClaim) (store.LinkResult, error) {
	var result store.LinkResult
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return result, fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)

	guest, err := linkTargetGuest(tx.QueryRow(ctx, linkTargetLockedQuery, userID))
	if err != nil {
		return result, err
	}
	var owner int64
	err = tx.QueryRow(ctx, "SELECT user_id FROM auth.identities WHERE provider = $1 AND subject = $2",
		claim.Provider, claim.Subject).Scan(&owner)
	switch {
	case err == nil:
		return result, store.ErrIdentityExists
	case !errors.Is(err, pgx.ErrNoRows):
		return result, err
	}
	// A guest takes the linked address as its own, so it is claimed like one.
	if claim.Provider == store.EmailProvider || guest {
		if result.Deleted, err = claimAddress(ctx, tx, userID, claim.Email); err != nil {
			return result, err
		}
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO auth.identities (user_id, provider, subject, email, email_verified)
		 VALUES ($1, $2, $3, $4, true) ON CONFLICT (provider, subject) DO NOTHING`,
		userID, claim.Provider, claim.Subject, claim.Email)
	if err != nil {
		return result, err
	}
	if tag.RowsAffected() == 0 {
		return result, store.ErrIdentityExists
	}
	if guest {
		if err := upgradeGuest(ctx, tx, userID, claim.Email); err != nil {
			return result, err
		}
		result.Upgraded = true
	}
	return result, tx.Commit(ctx)
}

// upgradeGuest gives a guest its proven address; the guest role becomes the
// default one, a role the project gave it stays.
func upgradeGuest(ctx context.Context, tx pgx.Tx, userID int64, email string) error {
	_, err := tx.Exec(ctx,
		`UPDATE auth.users SET email = $2, email_verified = true, email_verified_at = NOW(), is_guest = false,
		        allowed_roles = CASE WHEN role = $3 THEN NULL ELSE allowed_roles END,
		        role = CASE WHEN role = $3 THEN 'user' ELSE role END, updated_at = NOW()
		 WHERE id = $1 AND is_guest`, userID, email, store.GuestRole)
	return err
}

const (
	linkTargetQuery       = "SELECT email_verified AND email_verified_at IS NOT NULL, enabled, is_guest FROM auth.users WHERE id = $1"
	linkTargetLockedQuery = "SELECT email_verified AND email_verified_at IS NOT NULL, enabled, is_guest FROM auth.users WHERE id = $1 FOR UPDATE"
	listIdentitiesQuery   = `SELECT id, provider, COALESCE(email, ''), created_at, last_sign_in_at FROM auth.identities
		WHERE user_id = $1 ORDER BY id`
	listIdentitiesLockedQuery = `SELECT id, provider, COALESCE(email, ''), created_at, last_sign_in_at FROM auth.identities
		WHERE user_id = $1 ORDER BY id FOR UPDATE`
)

// linkTarget reads whether the account may take a link: enabled, with a
// proven address or none at all (a guest).
func linkTarget(_ context.Context, row pgx.Row) error {
	_, err := linkTargetGuest(row)
	return err
}

// linkTargetGuest is linkTarget that also says whether the account is a guest.
func linkTargetGuest(row pgx.Row) (bool, error) {
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

// claimAddress refuses an address the account itself, a proven account or a
// disabled one answers to, and deletes the unproven accounts answering to it.
func claimAddress(ctx context.Context, tx pgx.Tx, userID int64, email string) ([]int64, error) {
	rows, err := tx.Query(ctx,
		`SELECT id, (email_verified AND email_verified_at IS NOT NULL) OR NOT enabled FROM auth.users
		 WHERE lower(email) = lower($1) FOR UPDATE`, email)
	if err != nil {
		return nil, err
	}
	var squatters []int64
	for rows.Next() {
		var (
			id   int64
			held bool
		)
		if err := rows.Scan(&id, &held); err != nil {
			rows.Close()
			return nil, err
		}
		if id == userID || held {
			rows.Close()
			return nil, store.ErrIdentityExists
		}
		squatters = append(squatters, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(squatters) == 0 {
		return nil, err
	}
	_, err = tx.Exec(ctx, "DELETE FROM auth.users WHERE id = ANY($1)", squatters)
	return squatters, err
}

func (s *Store) ListIdentities(ctx context.Context, userID int64) ([]store.Identity, error) {
	return listIdentities(ctx, s.pool, userID, false)
}

func listIdentities(ctx context.Context, db querier, userID int64, forUpdate bool) ([]store.Identity, error) {
	query := listIdentitiesQuery
	if forUpdate {
		query = listIdentitiesLockedQuery
	}
	rows, err := db.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[store.Identity])
}

func (s *Store) UnlinkIdentity(ctx context.Context, userID, identityID int64) (store.Identity, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return store.Identity{}, fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)

	var hasPassword bool
	if err := tx.QueryRow(ctx, "SELECT password IS NOT NULL AND password NOT LIKE '!%' FROM auth.users WHERE id = $1 FOR UPDATE",
		userID).Scan(&hasPassword); err != nil {
		return store.Identity{}, notFound(err)
	}
	identities, err := listIdentities(ctx, tx, userID, true)
	if err != nil {
		return store.Identity{}, err
	}
	at := slices.IndexFunc(identities, func(identity store.Identity) bool { return identity.ID == identityID })
	switch {
	case at < 0:
		return store.Identity{}, store.ErrNotFound
	case len(identities) == 1 && !hasPassword:
		return store.Identity{}, store.ErrLastSignInMethod
	}
	if _, err := tx.Exec(ctx, "DELETE FROM auth.identities WHERE id = $1 AND user_id = $2", identityID, userID); err != nil {
		return store.Identity{}, err
	}
	return identities[at], tx.Commit(ctx)
}
