package handler

import (
	"context"
	"errors"
	"time"

	"github.com/excalibase/auth/internal/token"
	"github.com/jackc/pgx/v5/pgxpool"
)

// errTokenNotRedeemable covers every reason a link can't be used — unknown,
// already consumed, or expired. The three are deliberately indistinguishable to
// the caller so a probe can't tell "never existed" from "already used".
var errTokenNotRedeemable = errors.New("invalid_or_expired_token")

// singleUseTokenStore persists hashed, expiring, one-shot tokens.
//
// Queries are held as literals per table rather than assembled from a table
// name at call time: the SQL is then fully static and there is no path by which
// an identifier could ever be interpolated.
type singleUseTokenStore struct {
	insert       string
	selectByHash string
	consume      string
	invalidate   string
}

var emailVerificationTokens = singleUseTokenStore{
	insert: `INSERT INTO auth.email_verification_tokens (token_hash, user_id, expires_at, created_at)
	         VALUES ($1, $2, $3, NOW())`,
	selectByHash: `SELECT id, user_id, token_hash FROM auth.email_verification_tokens
	               WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > NOW()`,
	consume:    `UPDATE auth.email_verification_tokens SET consumed_at = NOW() WHERE id = $1`,
	invalidate: `UPDATE auth.email_verification_tokens SET consumed_at = NOW() WHERE user_id = $1 AND consumed_at IS NULL`,
}

var passwordResetTokens = singleUseTokenStore{
	insert: `INSERT INTO auth.password_reset_tokens (token_hash, user_id, expires_at, created_at)
	         VALUES ($1, $2, $3, NOW())`,
	selectByHash: `SELECT id, user_id, token_hash FROM auth.password_reset_tokens
	               WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > NOW()`,
	consume:    `UPDATE auth.password_reset_tokens SET consumed_at = NOW() WHERE id = $1`,
	invalidate: `UPDATE auth.password_reset_tokens SET consumed_at = NOW() WHERE user_id = $1 AND consumed_at IS NULL`,
}

// issue invalidates any outstanding tokens for the user and mints a new one.
// Returns the plaintext, which exists only in the email that follows — the
// database holds nothing but its hash.
func (s singleUseTokenStore) issue(ctx context.Context, db *pgxpool.Pool, userID int64, ttl time.Duration) (string, error) {
	plaintext, hash, err := token.New()
	if err != nil {
		return "", err
	}
	if err := s.invalidateAll(ctx, db, userID); err != nil {
		return "", err
	}
	if _, err := db.Exec(ctx, s.insert, hash, userID, time.Now().Add(ttl)); err != nil {
		return "", err
	}
	return plaintext, nil
}

// invalidateAll consumes every outstanding token for a user, so the newest link
// is always the only live one.
func (s singleUseTokenStore) invalidateAll(ctx context.Context, db *pgxpool.Pool, userID int64) error {
	_, err := db.Exec(ctx, s.invalidate, userID)
	return err
}

// redeem validates a plaintext token and marks it consumed, returning the user
// it belongs to. Returns errTokenNotRedeemable for unknown, expired, and
// already-used tokens alike.
func (s singleUseTokenStore) redeem(ctx context.Context, db *pgxpool.Pool, plaintext string) (int64, error) {
	if plaintext == "" {
		return 0, errTokenNotRedeemable
	}
	hash := token.Hash(plaintext)

	var rowID, userID int64
	var storedHash string
	if err := db.QueryRow(ctx, s.selectByHash, hash).Scan(&rowID, &userID, &storedHash); err != nil {
		return 0, errTokenNotRedeemable
	}
	// The row was found by an equality match the database performed; repeat it
	// in constant time so the decisive comparison carries no timing signal.
	if !token.Equal(storedHash, hash) {
		return 0, errTokenNotRedeemable
	}

	if _, err := db.Exec(ctx, s.consume, rowID); err != nil {
		return 0, errTokenNotRedeemable
	}
	return userID, nil
}
