package pgstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/excalibase/auth/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// foreignKeyViolation is Postgres's SQLSTATE for a row another table still references.
const foreignKeyViolation = "23503"

const profileQuery = "SELECT " + accountColumns + `, user_metadata, app_metadata, created_at, last_login_at
	FROM auth.users WHERE id = $1`

func scanProfile(row pgx.Row) (store.Profile, error) {
	var (
		profile   store.Profile
		user, app []byte
	)
	account := &profile.Account
	if err := row.Scan(&account.ID, &account.Email, &account.PasswordHash, &account.FullName, &account.Role,
		&account.AllowedRoles, &account.Enabled, &account.EmailVerified, &user, &app,
		&profile.CreatedAt, &profile.LastLoginAt); err != nil {
		return store.Profile{}, notFound(err)
	}
	profile.UserMetadata, profile.AppMetadata = store.MetadataObject(user), store.MetadataObject(app)
	return profile, nil
}

func (s *Store) Profile(ctx context.Context, userID int64) (store.Profile, error) {
	return scanProfile(s.pool.QueryRow(ctx, profileQuery, userID))
}

func (s *Store) UpdateProfile(ctx context.Context, userID int64, change store.ProfileChange) (store.Profile, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return store.Profile{}, fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)

	var user, app []byte
	if err := tx.QueryRow(ctx, "SELECT user_metadata, app_metadata FROM auth.users WHERE id = $1 FOR UPDATE",
		userID).Scan(&user, &app); err != nil {
		return store.Profile{}, notFound(err)
	}
	if user, err = mergeIfPatched(user, change.UserMetadata); err != nil {
		return store.Profile{}, err
	}
	if app, err = mergeIfPatched(app, change.AppMetadata); err != nil {
		return store.Profile{}, err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE auth.users SET full_name = COALESCE($2, full_name), user_metadata = $3::jsonb,
		        app_metadata = $4::jsonb, updated_at = NOW() WHERE id = $1`,
		userID, change.FullName, jsonText(user), jsonText(app)); err != nil {
		return store.Profile{}, err
	}
	profile, err := scanProfile(tx.QueryRow(ctx, profileQuery, userID))
	if err != nil {
		return store.Profile{}, err
	}
	return profile, tx.Commit(ctx)
}

// mergeIfPatched leaves stored metadata as it is when no patch was given.
func mergeIfPatched(stored []byte, patch map[string]json.RawMessage) ([]byte, error) {
	if patch == nil {
		return stored, nil
	}
	return store.MergeMetadata(stored, patch)
}

func jsonText(document []byte) *string {
	if document == nil {
		return nil
	}
	text := string(document)
	return &text
}

func (s *Store) ChangePassword(ctx context.Context, userID int64, passwordHash string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, "UPDATE auth.users SET password = $2, updated_at = NOW() WHERE id = $1", userID, passwordHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	if err := endSessionsAndLinks(ctx, tx, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, tokenTables[store.PasswordReset].invalidate, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) RevokeOtherSessions(ctx context.Context, userID int64, keep uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE auth.refresh_tokens SET revoked = true WHERE user_id = $1 AND family_id <> $2 AND revoked = false",
		userID, keep)
	return err
}

// referenced reads an app table's reference to a deleted account as ErrUserReferenced.
func referenced(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == foreignKeyViolation {
		return store.ErrUserReferenced
	}
	return err
}

func (s *Store) DeleteUser(ctx context.Context, userID int64) error {
	tag, err := s.pool.Exec(ctx, "DELETE FROM auth.users WHERE id = $1", userID)
	switch {
	case err != nil:
		return referenced(err)
	case tag.RowsAffected() == 0:
		return store.ErrNotFound
	}
	return nil
}
