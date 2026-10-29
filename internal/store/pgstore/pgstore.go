// Package pgstore keeps a Postgres project's end users in its auth schema.
// Connections carry search_path=auth.
package pgstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is store.Store over a pgx pool.
type Store struct {
	pool *pgxpool.Pool
}

var _ store.Store = (*Store)(nil)

// New wraps a pool whose connections reach the project's auth schema.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Pool is the underlying pool, for tests that read the database directly.
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// Close closes the pool; borrowed connections are waited for.
func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) InsertUser(ctx context.Context, email, passwordHash, fullName string) (int64, bool, error) {
	var id int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO users (email, password, full_name, role, enabled, created_at, updated_at)
		 SELECT $1, $2, $3, 'user', true, NOW(), NOW()
		 WHERE NOT EXISTS (SELECT 1 FROM auth.identities WHERE provider = $4 AND subject = $5)
		 ON CONFLICT (email) DO NOTHING RETURNING id`,
		email, passwordHash, fullName, store.EmailProvider, store.AddressKey(email),
	).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	return id, err == nil, err
}

func (s *Store) ReplaceUnverified(ctx context.Context, email, passwordHash, fullName string) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx,
		`UPDATE auth.users SET password = $2, full_name = $3, updated_at = NOW()
		 WHERE email = $1 AND email_verified = false RETURNING id`,
		email, passwordHash, fullName,
	).Scan(&id)
	return id, notFound(err)
}

func (s *Store) AccountByEmail(ctx context.Context, email string) (store.Account, error) {
	return scanAccount(s.pool.QueryRow(ctx, "SELECT "+accountColumns+" FROM users WHERE email = $1", email))
}

// accountColumns reads an account; a provider-made account has no password.
const accountColumns = "id, COALESCE(email, ''), COALESCE(password, ''), full_name, role, allowed_roles, enabled, email_verified, is_guest"

// accountFields are the scan targets of accountColumns, in order.
func accountFields(account *store.Account) []any {
	return []any{&account.ID, &account.Email, &account.PasswordHash, &account.FullName, &account.Role,
		&account.AllowedRoles, &account.Enabled, &account.EmailVerified, &account.IsGuest}
}

func scanAccount(row pgx.Row) (store.Account, error) {
	var account store.Account
	err := row.Scan(accountFields(&account)...)
	return account, notFound(err)
}

func (s *Store) AccountByID(ctx context.Context, id int64) (store.Account, error) {
	return scanAccount(s.pool.QueryRow(ctx, "SELECT "+accountColumns+" FROM auth.users WHERE id = $1", id))
}

func (s *Store) TouchLastLogin(ctx context.Context, userID int64) error {
	_, err := s.pool.Exec(ctx, "UPDATE users SET last_login_at = NOW() WHERE id = $1", userID)
	return err
}

func (s *Store) SetPassword(ctx context.Context, userID int64, passwordHash string) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE auth.users SET password = $1, updated_at = NOW() WHERE id = $2", passwordHash, userID)
	return err
}

func (s *Store) MarkVerified(ctx context.Context, userID int64, keepPassword bool, replacement string) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	var address string
	if err := tx.QueryRow(ctx,
		`UPDATE auth.users SET email_verified = true, email_verified_at = NOW(), updated_at = NOW(),
		        password = CASE WHEN $2 THEN password ELSE $3 END
		 WHERE id = $1 RETURNING COALESCE(email, '')`,
		userID, keepPassword, replacement,
	).Scan(&address); err != nil {
		return "", notFound(err)
	}
	if _, err := tx.Exec(ctx,
		"UPDATE auth.refresh_tokens SET revoked = true WHERE user_id = $1 AND revoked = false", userID); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, endChangesQuery, userID); err != nil {
		return "", err
	}
	return address, tx.Commit(ctx)
}

func (s *Store) ListUsers(ctx context.Context, limit, offset int) ([]domain.ManagedUser, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+managedUserColumns+" FROM auth.users ORDER BY id LIMIT $1 OFFSET $2", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]domain.ManagedUser, 0)
	for rows.Next() {
		user, err := scanManagedUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

const managedUserColumns = "id, COALESCE(email, ''), role, allowed_roles, enabled, email_verified, is_guest"

func scanManagedUser(row pgx.Row) (domain.ManagedUser, error) {
	var user domain.ManagedUser
	err := row.Scan(&user.ID, &user.Email, &user.Role, &user.AllowedRoles, &user.Enabled, &user.EmailVerified, &user.IsGuest)
	if user.AllowedRoles == nil {
		user.AllowedRoles = []string{user.Role}
	}
	return user, err
}

func (s *Store) ApplyRoleChange(ctx context.Context, change store.RoleChange) (domain.ManagedUser, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.ManagedUser{}, err
	}
	defer tx.Rollback(ctx)

	before, err := scanManagedUser(tx.QueryRow(ctx,
		"SELECT "+managedUserColumns+" FROM auth.users WHERE id = $1 FOR UPDATE", change.UserID))
	if err != nil {
		return domain.ManagedUser{}, notFound(err)
	}
	statements := []struct {
		sql  string
		args []any
	}{
		{`UPDATE auth.users SET role = $2, allowed_roles = $3, updated_at = NOW() WHERE id = $1`,
			[]any{change.UserID, change.Role, change.Stored}},
		{`UPDATE auth.refresh_tokens SET revoked = true WHERE user_id = $1 AND revoked = false`,
			[]any{change.UserID}},
		{endChangesQuery, []any{change.UserID}},
		{`INSERT INTO auth.role_changes (user_id, old_role, new_role, old_allowed_roles, new_allowed_roles, actor)
		  VALUES ($1, $2, $3, $4, $5, $6)`,
			[]any{change.UserID, before.Role, change.Role, before.AllowedRoles, change.Allowed, change.Actor}},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
			return domain.ManagedUser{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.ManagedUser{}, err
	}
	after := before
	after.Role, after.AllowedRoles = change.Role, change.Allowed
	return after, nil
}

func (s *Store) InsertRefreshToken(ctx context.Context, hash string, userID int64, session store.RefreshSession) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO auth.refresh_tokens (token_hash, family_id, user_id, expiry_date, last_auth_at, created_at, revoked)
		 VALUES ($1, $2, $3, $4, $5, NOW(), false)`,
		hash, session.FamilyID, userID, session.Expiry, authTime(session),
	)
	return err
}

// authTime is the session's sign-in time, NULL when it predates the column.
func authTime(session store.RefreshSession) *time.Time {
	if session.AuthTime.IsZero() {
		return nil
	}
	return &session.AuthTime
}

// RotateRefreshToken revokes the live token in one statement, so of two
// concurrent uses exactly one gets a row back.
func (s *Store) RotateRefreshToken(ctx context.Context, presented, successor string, accept func(store.Account) error) (store.Account, store.RefreshSession, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return store.Account{}, store.RefreshSession{}, fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)

	var (
		userID   int64
		session  store.RefreshSession
		signedIn *time.Time
	)
	if err := tx.QueryRow(ctx,
		`UPDATE auth.refresh_tokens SET revoked = true
		 WHERE token_hash = $1 AND revoked = false AND expiry_date > NOW()
		 RETURNING user_id, family_id, expiry_date, last_auth_at`,
		presented,
	).Scan(&userID, &session.FamilyID, &session.Expiry, &signedIn); err != nil {
		return store.Account{}, store.RefreshSession{}, notFound(err)
	}
	if signedIn != nil {
		session.AuthTime = *signedIn
	}
	account, err := scanAccount(tx.QueryRow(ctx, "SELECT "+accountColumns+" FROM auth.users WHERE id = $1", userID))
	if err != nil {
		return store.Account{}, store.RefreshSession{}, store.ErrNoAccount
	}
	account.PasswordHash = ""
	if err := accept(account); err != nil {
		return store.Account{}, store.RefreshSession{}, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO auth.refresh_tokens (token_hash, family_id, user_id, expiry_date, last_auth_at, created_at, revoked)
		 VALUES ($1, $2, $3, $4, $5, NOW(), false)`,
		successor, session.FamilyID, userID, session.Expiry, signedIn,
	); err != nil {
		return store.Account{}, store.RefreshSession{}, err
	}
	return account, session, tx.Commit(ctx)
}

func (s *Store) RefreshTokenState(ctx context.Context, hash string) (store.RefreshState, error) {
	var state store.RefreshState
	err := s.pool.QueryRow(ctx,
		"SELECT revoked, family_id, user_id FROM auth.refresh_tokens WHERE token_hash = $1", hash,
	).Scan(&state.Revoked, &state.FamilyID, &state.UserID)
	return state, notFound(err)
}

func (s *Store) RevokeRefreshFamily(ctx context.Context, familyID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE auth.refresh_tokens SET revoked = true WHERE family_id = $1 AND revoked = false", familyID)
	return err
}

func (s *Store) RevokeRefreshToken(ctx context.Context, hash string) error {
	_, err := s.pool.Exec(ctx, "UPDATE auth.refresh_tokens SET revoked = true WHERE token_hash = $1", hash)
	return err
}

// RevokeUserRefreshTokens also ends the links the account has in flight, which
// a session it no longer holds may have started.
func (s *Store) RevokeUserRefreshTokens(ctx context.Context, userID int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	defer tx.Rollback(ctx)
	if err := endSessionsAndLinks(ctx, tx, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func endSessionsAndLinks(ctx context.Context, tx pgx.Tx, userID int64) error {
	for _, statement := range []string{
		"UPDATE auth.refresh_tokens SET revoked = true WHERE user_id = $1 AND revoked = false",
		"DELETE FROM auth.flow_states WHERE link_user_id = $1",
		"DELETE FROM auth.auth_codes WHERE user_id = $1 AND link_provider IS NOT NULL",
		"UPDATE auth.email_otps SET consumed_at = NOW() WHERE link_user_id = $1 AND consumed_at IS NULL",
		endChangesQuery,
	} {
		if _, err := tx.Exec(ctx, statement, userID); err != nil {
			return err
		}
	}
	return nil
}

// tokenQueries are literals per table, so no identifier is ever interpolated.
type tokenQueries struct {
	insert, selectByHash, consume, invalidate string
}

var tokenTables = map[store.TokenKind]tokenQueries{
	store.EmailVerification: {
		insert: `INSERT INTO auth.email_verification_tokens (token_hash, user_id, expires_at, confirms_password, created_at)
		         VALUES ($1, $2, $3, $4, NOW())`,
		selectByHash: `SELECT id, user_id, token_hash, confirms_password FROM auth.email_verification_tokens
		               WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > NOW()`,
		consume:    `UPDATE auth.email_verification_tokens SET consumed_at = NOW() WHERE id = $1 AND consumed_at IS NULL`,
		invalidate: `UPDATE auth.email_verification_tokens SET consumed_at = NOW() WHERE user_id = $1 AND consumed_at IS NULL`,
	},
	store.PasswordReset: {
		insert: `INSERT INTO auth.password_reset_tokens (token_hash, user_id, expires_at, created_at)
		         VALUES ($1, $2, $3, NOW())`,
		selectByHash: `SELECT id, user_id, token_hash, false FROM auth.password_reset_tokens
		               WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > NOW()`,
		consume:    `UPDATE auth.password_reset_tokens SET consumed_at = NOW() WHERE id = $1 AND consumed_at IS NULL`,
		invalidate: `UPDATE auth.password_reset_tokens SET consumed_at = NOW() WHERE user_id = $1 AND consumed_at IS NULL`,
	},
}

var errUnknownTokenKind = errors.New("unknown token kind")

func queriesFor(kind store.TokenKind) (tokenQueries, error) {
	queries, ok := tokenTables[kind]
	if !ok {
		return tokenQueries{}, errUnknownTokenKind
	}
	return queries, nil
}

func (s *Store) IssueToken(ctx context.Context, kind store.TokenKind, userID int64, hash string, expiresAt time.Time, confirmsPassword bool) error {
	queries, err := queriesFor(kind)
	if err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, queries.invalidate, userID); err != nil {
		return err
	}
	args := []any{hash, userID, expiresAt}
	if kind == store.EmailVerification {
		args = append(args, confirmsPassword)
	}
	_, err = s.pool.Exec(ctx, queries.insert, args...)
	return err
}

func (s *Store) LookupToken(ctx context.Context, kind store.TokenKind, hash string) (store.SingleUseToken, error) {
	queries, err := queriesFor(kind)
	if err != nil {
		return store.SingleUseToken{}, err
	}
	var found store.SingleUseToken
	err = s.pool.QueryRow(ctx, queries.selectByHash, hash).Scan(&found.RowID, &found.UserID, &found.Hash, &found.ConfirmsPassword)
	return found, notFound(err)
}

func (s *Store) ClaimToken(ctx context.Context, kind store.TokenKind, rowID int64) (bool, error) {
	queries, err := queriesFor(kind)
	if err != nil {
		return false, err
	}
	tag, err := s.pool.Exec(ctx, queries.consume, rowID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) CreateAPIKey(ctx context.Context, hash, prefix, keyType, name string) (int64, time.Time, error) {
	var (
		id        int64
		createdAt time.Time
	)
	err := s.pool.QueryRow(ctx,
		`INSERT INTO auth.api_keys (key_hash, key_prefix, key_type, name)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, created_at`,
		hash, prefix, keyType, name,
	).Scan(&id, &createdAt)
	return id, createdAt, err
}

func (s *Store) ListAPIKeys(ctx context.Context) ([]store.APIKeyListing, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, key_prefix, key_type, COALESCE(name, ''), created_at, last_used_at
		 FROM auth.api_keys
		 WHERE revoked_at IS NULL
		 ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := make([]store.APIKeyListing, 0)
	for rows.Next() {
		var key store.APIKeyListing
		if err := rows.Scan(&key.ID, &key.Prefix, &key.Type, &key.Name, &key.CreatedAt, &key.LastUsedAt); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *Store) RevokeAPIKey(ctx context.Context, id int64) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE auth.api_keys
		 SET revoked_at = NOW()
		 WHERE id = $1 AND revoked_at IS NULL`,
		id,
	)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) APIKeyByHash(ctx context.Context, hash string) (store.APIKey, error) {
	var key store.APIKey
	err := s.pool.QueryRow(ctx,
		"SELECT id, key_type, created_by FROM auth.api_keys WHERE key_hash = $1 AND revoked_at IS NULL",
		hash,
	).Scan(&key.ID, &key.Type, &key.CreatedBy)
	return key, notFound(err)
}

func (s *Store) TouchAPIKey(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, "UPDATE auth.api_keys SET last_used_at = NOW() WHERE id = $1", id)
	return err
}
