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

func (s *Store) LinkIdentity(ctx context.Context, userID int64, claim store.IdentityClaim) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)

	if err := lockLinkTarget(ctx, tx, userID); err != nil {
		return err
	}
	var owner int64
	err = tx.QueryRow(ctx, "SELECT user_id FROM auth.identities WHERE provider = $1 AND subject = $2",
		claim.Provider, claim.Subject).Scan(&owner)
	switch {
	case err == nil:
		return store.ErrIdentityExists
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}
	if claim.Provider == store.EmailProvider {
		if err := claimAddress(ctx, tx, userID, claim.Email); err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO auth.identities (user_id, provider, subject, email, email_verified)
		 VALUES ($1, $2, $3, $4, true) ON CONFLICT (provider, subject) DO NOTHING`,
		userID, claim.Provider, claim.Subject, claim.Email)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrIdentityExists
	}
	return tx.Commit(ctx)
}

// lockLinkTarget holds the account for the link: enabled, with a proven address.
func lockLinkTarget(ctx context.Context, tx pgx.Tx, userID int64) error {
	var proven, enabled bool
	err := tx.QueryRow(ctx,
		"SELECT email_verified AND email_verified_at IS NOT NULL, enabled FROM auth.users WHERE id = $1 FOR UPDATE",
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

// claimAddress refuses an address the account itself, a proven account or a
// disabled one answers to, and deletes the unproven accounts answering to it.
func claimAddress(ctx context.Context, tx pgx.Tx, userID int64, email string) error {
	rows, err := tx.Query(ctx,
		`SELECT id, (email_verified AND email_verified_at IS NOT NULL) OR NOT enabled FROM auth.users
		 WHERE lower(email) = lower($1) FOR UPDATE`, email)
	if err != nil {
		return err
	}
	var squatters []int64
	for rows.Next() {
		var (
			id   int64
			held bool
		)
		if err := rows.Scan(&id, &held); err != nil {
			rows.Close()
			return err
		}
		if id == userID || held {
			rows.Close()
			return store.ErrIdentityExists
		}
		squatters = append(squatters, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(squatters) == 0 {
		return nil
	}
	_, err = tx.Exec(ctx, "DELETE FROM auth.users WHERE id = ANY($1)", squatters)
	return err
}

func (s *Store) ListIdentities(ctx context.Context, userID int64) ([]store.Identity, error) {
	return listIdentities(ctx, s.pool, userID, "")
}

func listIdentities(ctx context.Context, db querier, userID int64, lock string) ([]store.Identity, error) {
	rows, err := db.Query(ctx,
		`SELECT id, provider, COALESCE(email, ''), created_at, last_sign_in_at FROM auth.identities
		 WHERE user_id = $1 ORDER BY id`+lock, userID)
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
	if err := tx.QueryRow(ctx, "SELECT password IS NOT NULL FROM auth.users WHERE id = $1 FOR UPDATE",
		userID).Scan(&hasPassword); err != nil {
		return store.Identity{}, notFound(err)
	}
	identities, err := listIdentities(ctx, tx, userID, " FOR UPDATE")
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
