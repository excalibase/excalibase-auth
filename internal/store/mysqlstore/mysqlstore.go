// Package mysqlstore keeps a MySQL project's end users in the auth database
// of the project's own instance (ADR 0041). It behaves as pgstore does; where
// MySQL has no RETURNING or ON CONFLICT, a transaction with a locking read
// gives the same outcome.
package mysqlstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/store"
	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
)

// duplicateEntry is MySQL's ER_DUP_ENTRY.
const duplicateEntry = 1062

// ioTimeout bounds one read or write on a connection; every auth statement
// is a short keyed read or write.
const ioTimeout = 10 * time.Second

// Login is the auth_admin record provisioning files for a MySQL project.
type Login struct {
	Host, Port, Database, Username, Password string
	// ServerCA is the PEM of the project's CA; the server is verified against
	// it and against Host.
	ServerCA string
}

// Config is the connection for a login: TLS verified against the project's CA
// and host, UTC times, strict SQL mode, no multi-statements. Errors never carry the login.
func Config(login Login) (*mysql.Config, error) {
	if strings.TrimSpace(login.ServerCA) == "" {
		return nil, errors.New("mysql credential record lacks sslrootcert; the server cannot be verified")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(login.ServerCA)) {
		return nil, errors.New("mysql sslrootcert holds no PEM certificate")
	}
	config := mysql.NewConfig()
	config.User, config.Passwd = login.Username, login.Password
	config.Net, config.Addr = "tcp", net.JoinHostPort(login.Host, login.Port)
	config.DBName = login.Database
	config.TLS = &tls.Config{RootCAs: roots, ServerName: login.Host, MinVersion: tls.VersionTLS12}
	config.ParseTime = true
	config.Loc = time.UTC
	config.Params = map[string]string{
		"time_zone": "'+00:00'",
		// Strict whatever the instance's own mode: an over-long or invalid
		// value fails, as on Postgres, instead of being cut or zeroed.
		"sql_mode": "'STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'",
	}
	config.Timeout = 10 * time.Second
	// A server that stops answering (its pod replaced by a restore) fails
	// the call instead of holding it until the edge answers 504 (EXC-650).
	config.ReadTimeout = ioTimeout
	config.WriteTimeout = ioTimeout
	return config, nil
}

// Store is store.Store over a MySQL connection pool.
type Store struct {
	db *sql.DB
}

var _ store.Store = (*Store)(nil)

// Open builds the pool; connections are made on first use.
func Open(config *mysql.Config) (*Store, error) {
	connector, err := mysql.NewConnector(config)
	if err != nil {
		return nil, errors.New("mysql connection could not be configured")
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)
	return &Store{db: db}, nil
}

// Close closes the pool.
func (s *Store) Close() {
	if s.db != nil {
		_ = s.db.Close()
	}
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

// inTx runs fn in a transaction, committing only when it returns nil.
func (s *Store) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// roles is a JSON array column; NULL reads as nil.
func encodeRoles(roles []string) (any, error) {
	if roles == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(roles)
	return string(encoded), err
}

func decodeRoles(raw sql.NullString) ([]string, error) {
	if !raw.Valid {
		return nil, nil
	}
	var roles []string
	if err := json.Unmarshal([]byte(raw.String), &roles); err != nil {
		return nil, err
	}
	if roles == nil {
		roles = []string{}
	}
	return roles, nil
}

func (s *Store) InsertUser(ctx context.Context, email, passwordHash, fullName string) (int64, bool, error) {
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO users (email, password, full_name, role, enabled, created_at, updated_at)
		 SELECT ?, ?, ?, 'user', TRUE, NOW(6), NOW(6) FROM DUAL
		 WHERE NOT EXISTS (SELECT 1 FROM identities WHERE provider = ? AND subject = ?)`,
		email, passwordHash, fullName, store.EmailProvider, store.AddressKey(email))
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) && mysqlErr.Number == duplicateEntry {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if inserted, err := result.RowsAffected(); err != nil || inserted == 0 {
		return 0, false, err
	}
	id, err := result.LastInsertId()
	return id, err == nil, err
}

func (s *Store) ReplaceUnverified(ctx context.Context, email, passwordHash, fullName string) (int64, error) {
	var id int64
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx,
			"SELECT id FROM users WHERE email = ? AND email_verified = FALSE FOR UPDATE", email,
		).Scan(&id); err != nil {
			return notFound(err)
		}
		_, err := tx.ExecContext(ctx,
			"UPDATE users SET password = ?, full_name = ?, updated_at = NOW(6) WHERE id = ?",
			passwordHash, fullName, id)
		return err
	})
	return id, err
}

// accountColumns reads an account; a provider-made account has no password.
const accountColumns = "id, COALESCE(email, ''), COALESCE(password, ''), full_name, role, allowed_roles, enabled, email_verified"

func scanAccount(row rowScanner) (store.Account, error) {
	var (
		account store.Account
		allowed sql.NullString
	)
	if err := row.Scan(&account.ID, &account.Email, &account.PasswordHash, &account.FullName, &account.Role,
		&allowed, &account.Enabled, &account.EmailVerified); err != nil {
		return store.Account{}, notFound(err)
	}
	var err error
	account.AllowedRoles, err = decodeRoles(allowed)
	return account, err
}

func (s *Store) AccountByEmail(ctx context.Context, email string) (store.Account, error) {
	return scanAccount(s.db.QueryRowContext(ctx, "SELECT "+accountColumns+" FROM users WHERE email = ?", email))
}

func (s *Store) AccountByID(ctx context.Context, id int64) (store.Account, error) {
	return scanAccount(s.db.QueryRowContext(ctx, "SELECT "+accountColumns+" FROM users WHERE id = ?", id))
}

func (s *Store) TouchLastLogin(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE users SET last_login_at = NOW(6) WHERE id = ?", userID)
	return err
}

func (s *Store) SetPassword(ctx context.Context, userID int64, passwordHash string) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE users SET password = ?, updated_at = NOW(6) WHERE id = ?", passwordHash, userID)
	return err
}

func (s *Store) MarkVerified(ctx context.Context, userID int64, keepPassword bool, replacement string) (string, error) {
	var address string
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, "SELECT email FROM users WHERE id = ? FOR UPDATE", userID).Scan(&address); err != nil {
			return notFound(err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE users SET email_verified = TRUE, email_verified_at = NOW(6), updated_at = NOW(6),
			        password = IF(?, password, ?)
			 WHERE id = ?`,
			keepPassword, replacement, userID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx,
			"UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = ? AND revoked = FALSE", userID)
		return err
	})
	return address, err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanManagedUser(row rowScanner) (domain.ManagedUser, error) {
	var (
		user    domain.ManagedUser
		allowed sql.NullString
	)
	if err := row.Scan(&user.ID, &user.Email, &user.Role, &allowed, &user.Enabled, &user.EmailVerified); err != nil {
		return domain.ManagedUser{}, err
	}
	roles, err := decodeRoles(allowed)
	if err != nil {
		return domain.ManagedUser{}, err
	}
	user.AllowedRoles = roles
	if user.AllowedRoles == nil {
		user.AllowedRoles = []string{user.Role}
	}
	return user, nil
}

func (s *Store) ListUsers(ctx context.Context, limit, offset int) ([]domain.ManagedUser, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, email, role, allowed_roles, enabled, email_verified
		 FROM users ORDER BY id LIMIT ? OFFSET ?`, limit, offset)
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

func (s *Store) ApplyRoleChange(ctx context.Context, change store.RoleChange) (domain.ManagedUser, error) {
	stored, err := encodeRoles(change.Stored)
	if err != nil {
		return domain.ManagedUser{}, err
	}
	newAllowed, err := encodeRoles(change.Allowed)
	if err != nil {
		return domain.ManagedUser{}, err
	}
	var before domain.ManagedUser
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		var err error
		before, err = scanManagedUser(tx.QueryRowContext(ctx,
			`SELECT id, email, role, allowed_roles, enabled, email_verified
			 FROM users WHERE id = ? FOR UPDATE`, change.UserID))
		if err != nil {
			return notFound(err)
		}
		oldAllowed, err := encodeRoles(before.AllowedRoles)
		if err != nil {
			return err
		}
		statements := []struct {
			sql  string
			args []any
		}{
			{"UPDATE users SET role = ?, allowed_roles = ?, updated_at = NOW(6) WHERE id = ?",
				[]any{change.Role, stored, change.UserID}},
			{"UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = ? AND revoked = FALSE",
				[]any{change.UserID}},
			{`INSERT INTO role_changes (user_id, old_role, new_role, old_allowed_roles, new_allowed_roles, actor)
			  VALUES (?, ?, ?, ?, ?, ?)`,
				[]any{change.UserID, before.Role, change.Role, oldAllowed, newAllowed, change.Actor}},
		}
		for _, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return domain.ManagedUser{}, err
	}
	after := before
	after.Role, after.AllowedRoles = change.Role, change.Allowed
	return after, nil
}

const insertRefreshToken = `INSERT INTO refresh_tokens (token_hash, family_id, user_id, expiry_date, last_auth_at, created_at, revoked)
	VALUES (?, ?, ?, ?, ?, NOW(6), FALSE)`

func (s *Store) InsertRefreshToken(ctx context.Context, hash string, userID int64, session store.RefreshSession) error {
	_, err := s.db.ExecContext(ctx, insertRefreshToken, hash, session.FamilyID.String(), userID, session.Expiry, authTime(session))
	return err
}

// authTime is the session's sign-in time, NULL when it predates the column.
func authTime(session store.RefreshSession) any {
	if session.AuthTime.IsZero() {
		return nil
	}
	return session.AuthTime.UTC()
}

// RotateRefreshToken locks the live row before revoking it: a concurrent
// rotation waits, then reads it revoked, so exactly one succeeds.
func (s *Store) RotateRefreshToken(ctx context.Context, presented, successor string, accept func(store.Account) error) (store.Account, store.RefreshSession, error) {
	var (
		account store.Account
		session store.RefreshSession
	)
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var (
			userID   int64
			family   string
			signedIn sql.NullTime
		)
		if err := tx.QueryRowContext(ctx,
			`SELECT user_id, family_id, expiry_date, last_auth_at FROM refresh_tokens
			 WHERE token_hash = ? AND revoked = FALSE AND expiry_date > NOW(6) FOR UPDATE`,
			presented,
		).Scan(&userID, &family, &session.Expiry, &signedIn); err != nil {
			return notFound(err)
		}
		session.AuthTime = signedIn.Time
		familyID, err := uuid.Parse(family)
		if err != nil {
			return err
		}
		session.FamilyID = familyID
		result, err := tx.ExecContext(ctx,
			"UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = ? AND revoked = FALSE", presented)
		if err != nil {
			return err
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			return store.ErrNotFound
		}
		if account, err = s.rotatingAccount(ctx, tx, userID); err != nil {
			return err
		}
		if err := accept(account); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, insertRefreshToken, successor, session.FamilyID.String(), userID, session.Expiry, authTime(session))
		return err
	})
	if err != nil {
		return store.Account{}, store.RefreshSession{}, err
	}
	return account, session, nil
}

func (s *Store) rotatingAccount(ctx context.Context, tx *sql.Tx, userID int64) (store.Account, error) {
	var (
		account store.Account
		allowed sql.NullString
	)
	if err := tx.QueryRowContext(ctx,
		"SELECT id, email, full_name, role, allowed_roles, email_verified FROM users WHERE id = ?", userID,
	).Scan(&account.ID, &account.Email, &account.FullName, &account.Role, &allowed, &account.EmailVerified); err != nil {
		return store.Account{}, store.ErrNoAccount
	}
	roles, err := decodeRoles(allowed)
	if err != nil {
		return store.Account{}, err
	}
	account.AllowedRoles = roles
	return account, nil
}

func (s *Store) RefreshTokenState(ctx context.Context, hash string) (store.RefreshState, error) {
	var (
		state  store.RefreshState
		family string
	)
	if err := s.db.QueryRowContext(ctx,
		"SELECT revoked, family_id FROM refresh_tokens WHERE token_hash = ?", hash,
	).Scan(&state.Revoked, &family); err != nil {
		return store.RefreshState{}, notFound(err)
	}
	familyID, err := uuid.Parse(family)
	state.FamilyID = familyID
	return state, err
}

func (s *Store) RevokeRefreshFamily(ctx context.Context, familyID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE refresh_tokens SET revoked = TRUE WHERE family_id = ? AND revoked = FALSE", familyID.String())
	return err
}

func (s *Store) RevokeRefreshToken(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = ?", hash)
	return err
}

// RevokeUserRefreshTokens also ends the links in flight; see pgstore.
func (s *Store) RevokeUserRefreshTokens(ctx context.Context, userID int64) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for _, statement := range []string{
			"UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = ? AND revoked = FALSE",
			"DELETE FROM flow_states WHERE link_user_id = ?",
			"DELETE FROM auth_codes WHERE user_id = ? AND link_provider IS NOT NULL",
			"DELETE FROM email_otps WHERE link_user_id = ?",
		} {
			if _, err := tx.ExecContext(ctx, statement, userID); err != nil {
				return err
			}
		}
		return nil
	})
}

// tokenQueries are literals per table, so no identifier is ever interpolated.
type tokenQueries struct {
	insert, selectByHash, consume, invalidate string
}

var tokenTables = map[store.TokenKind]tokenQueries{
	store.EmailVerification: {
		insert: `INSERT INTO email_verification_tokens (token_hash, user_id, expires_at, confirms_password, created_at)
		         VALUES (?, ?, ?, ?, NOW(6))`,
		selectByHash: `SELECT id, user_id, token_hash, confirms_password FROM email_verification_tokens
		               WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > NOW(6)`,
		consume:    "UPDATE email_verification_tokens SET consumed_at = NOW(6) WHERE id = ? AND consumed_at IS NULL",
		invalidate: "UPDATE email_verification_tokens SET consumed_at = NOW(6) WHERE user_id = ? AND consumed_at IS NULL",
	},
	store.PasswordReset: {
		insert: `INSERT INTO password_reset_tokens (token_hash, user_id, expires_at, created_at)
		         VALUES (?, ?, ?, NOW(6))`,
		selectByHash: `SELECT id, user_id, token_hash, FALSE FROM password_reset_tokens
		               WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > NOW(6)`,
		consume:    "UPDATE password_reset_tokens SET consumed_at = NOW(6) WHERE id = ? AND consumed_at IS NULL",
		invalidate: "UPDATE password_reset_tokens SET consumed_at = NOW(6) WHERE user_id = ? AND consumed_at IS NULL",
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
	if _, err := s.db.ExecContext(ctx, queries.invalidate, userID); err != nil {
		return err
	}
	args := []any{hash, userID, expiresAt}
	if kind == store.EmailVerification {
		args = append(args, confirmsPassword)
	}
	_, err = s.db.ExecContext(ctx, queries.insert, args...)
	return err
}

func (s *Store) LookupToken(ctx context.Context, kind store.TokenKind, hash string) (store.SingleUseToken, error) {
	queries, err := queriesFor(kind)
	if err != nil {
		return store.SingleUseToken{}, err
	}
	var found store.SingleUseToken
	err = s.db.QueryRowContext(ctx, queries.selectByHash, hash).Scan(&found.RowID, &found.UserID, &found.Hash, &found.ConfirmsPassword)
	return found, notFound(err)
}

func (s *Store) ClaimToken(ctx context.Context, kind store.TokenKind, rowID int64) (bool, error) {
	queries, err := queriesFor(kind)
	if err != nil {
		return false, err
	}
	result, err := s.db.ExecContext(ctx, queries.consume, rowID)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	return changed == 1, err
}

func (s *Store) CreateAPIKey(ctx context.Context, hash, prefix, keyType, name string) (int64, time.Time, error) {
	var (
		id        int64
		createdAt time.Time
	)
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx,
			"INSERT INTO api_keys (key_hash, key_prefix, key_type, name) VALUES (?, ?, ?, ?)",
			hash, prefix, keyType, name)
		if err != nil {
			return err
		}
		if id, err = result.LastInsertId(); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, "SELECT created_at FROM api_keys WHERE id = ?", id).Scan(&createdAt)
	})
	return id, createdAt, err
}

func (s *Store) ListAPIKeys(ctx context.Context) ([]store.APIKeyListing, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, key_prefix, key_type, COALESCE(name, ''), created_at, last_used_at
		 FROM api_keys
		 WHERE revoked_at IS NULL
		 ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := make([]store.APIKeyListing, 0)
	for rows.Next() {
		var (
			key      store.APIKeyListing
			lastUsed sql.NullTime
		)
		if err := rows.Scan(&key.ID, &key.Prefix, &key.Type, &key.Name, &key.CreatedAt, &lastUsed); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			used := lastUsed.Time
			key.LastUsedAt = &used
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *Store) RevokeAPIKey(ctx context.Context, id int64) (bool, error) {
	result, err := s.db.ExecContext(ctx,
		"UPDATE api_keys SET revoked_at = NOW(6) WHERE id = ? AND revoked_at IS NULL", id)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	return changed > 0, err
}

func (s *Store) APIKeyByHash(ctx context.Context, hash string) (store.APIKey, error) {
	var (
		key       store.APIKey
		createdBy sql.NullInt64
	)
	if err := s.db.QueryRowContext(ctx,
		"SELECT id, key_type, created_by FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL", hash,
	).Scan(&key.ID, &key.Type, &createdBy); err != nil {
		return store.APIKey{}, notFound(err)
	}
	if createdBy.Valid {
		owner := createdBy.Int64
		key.CreatedBy = &owner
	}
	return key, nil
}

func (s *Store) TouchAPIKey(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE api_keys SET last_used_at = NOW(6) WHERE id = ?", id)
	return err
}
