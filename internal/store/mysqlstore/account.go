package mysqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/excalibase/auth/internal/store"
	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
)

// rowIsReferenced is MySQL's ER_ROW_IS_REFERENCED_2.
const rowIsReferenced = 1451

const profileQuery = "SELECT " + accountColumns + `, user_metadata, app_metadata, created_at, last_login_at
	FROM users WHERE id = ?`

func scanProfile(row rowScanner) (store.Profile, error) {
	var (
		profile      store.Profile
		read         accountRow
		user, app    []byte
		lastLoggedIn sql.NullTime
	)
	if err := row.Scan(append(read.fields(), &user, &app, &profile.CreatedAt, &lastLoggedIn)...); err != nil {
		return store.Profile{}, notFound(err)
	}
	account, err := read.decoded()
	if err != nil {
		return store.Profile{}, err
	}
	profile.Account = account
	if lastLoggedIn.Valid {
		profile.LastLoginAt = &lastLoggedIn.Time
	}
	profile.UserMetadata, profile.AppMetadata = store.MetadataObject(user), store.MetadataObject(app)
	return profile, nil
}

func (s *Store) Profile(ctx context.Context, userID int64) (store.Profile, error) {
	return scanProfile(s.db.QueryRowContext(ctx, profileQuery, userID))
}

func (s *Store) UpdateProfile(ctx context.Context, userID int64, change store.ProfileChange) (store.Profile, error) {
	var profile store.Profile
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var user, app []byte
		if err := tx.QueryRowContext(ctx, "SELECT user_metadata, app_metadata FROM users WHERE id = ? FOR UPDATE",
			userID).Scan(&user, &app); err != nil {
			return notFound(err)
		}
		var err error
		if user, err = mergeIfPatched(user, change.UserMetadata); err != nil {
			return err
		}
		if app, err = mergeIfPatched(app, change.AppMetadata); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE users SET full_name = COALESCE(?, full_name), user_metadata = ?, app_metadata = ?, updated_at = NOW(6)
			 WHERE id = ?`, change.FullName, jsonText(user), jsonText(app), userID); err != nil {
			return err
		}
		profile, err = scanProfile(tx.QueryRowContext(ctx, profileQuery, userID))
		return err
	})
	return profile, err
}

func mergeIfPatched(stored []byte, patch map[string]json.RawMessage) ([]byte, error) {
	if patch == nil {
		return stored, nil
	}
	return store.MergeMetadata(stored, patch)
}

// jsonText is a document as a JSON column takes it; nil stays NULL.
func jsonText(document []byte) any {
	if document == nil {
		return nil
	}
	return string(document)
}

func (s *Store) ChangePassword(ctx context.Context, userID int64, passwordHash string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var id int64
		if err := tx.QueryRowContext(ctx, "SELECT id FROM users WHERE id = ? FOR UPDATE", userID).Scan(&id); err != nil {
			return notFound(err)
		}
		if _, err := tx.ExecContext(ctx, "UPDATE users SET password = ?, updated_at = NOW(6) WHERE id = ?",
			passwordHash, userID); err != nil {
			return err
		}
		if err := endSessionsAndLinks(ctx, tx, userID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, tokenTables[store.PasswordReset].invalidate, userID)
		return err
	})
}

func (s *Store) RevokeOtherSessions(ctx context.Context, userID int64, keep uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = ? AND family_id <> ? AND revoked = FALSE",
		userID, keep.String())
	return err
}

// referenced reads an app table's reference to a deleted account as ErrUserReferenced.
func referenced(err error) error {
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) && mysqlErr.Number == rowIsReferenced {
		return store.ErrUserReferenced
	}
	return err
}

func (s *Store) DeleteUser(ctx context.Context, userID int64) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return referenced(err)
	}
	deleted, err := result.RowsAffected()
	if err == nil && deleted == 0 {
		return store.ErrNotFound
	}
	return err
}
