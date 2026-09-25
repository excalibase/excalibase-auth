package handler

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/excalibase/auth/internal/token"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errRefreshTokenStore = errors.New("failed to store refresh token")

// refreshSession is one login: every token rotated from it shares the family
// and the expiry, so rotation can neither outlive the login nor hide a replay.
type refreshSession struct {
	familyID uuid.UUID
	expiry   time.Time
}

type rotatedRefreshToken struct {
	userID  int64
	session refreshSession
}

type sqlExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func (h *AuthHandler) newRefreshSession() refreshSession {
	return refreshSession{
		familyID: uuid.New(),
		expiry:   time.Now().Add(time.Duration(h.refreshExp) * time.Second),
	}
}

// storeRefreshToken mints a token in the session and persists only its hash.
func storeRefreshToken(ctx context.Context, db sqlExecer, userID int64, session refreshSession) (string, error) {
	plaintext, hash, err := token.New()
	if err != nil {
		return "", err
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO auth.refresh_tokens (token_hash, family_id, user_id, expiry_date, created_at, revoked)
		 VALUES ($1, $2, $3, $4, NOW(), false)`,
		hash, session.familyID, userID, session.expiry,
	); err != nil {
		return "", err
	}
	return plaintext, nil
}

// consumeRefreshToken revokes a live token in one statement, so of two
// concurrent uses exactly one gets a row back. pgx.ErrNoRows means the token
// is unknown, expired, or already used.
func consumeRefreshToken(ctx context.Context, tx pgx.Tx, hash string) (rotatedRefreshToken, error) {
	var rotated rotatedRefreshToken
	err := tx.QueryRow(ctx,
		`UPDATE auth.refresh_tokens SET revoked = true
		 WHERE token_hash = $1 AND revoked = false AND expiry_date > NOW()
		 RETURNING user_id, family_id, expiry_date`,
		hash,
	).Scan(&rotated.userID, &rotated.session.familyID, &rotated.session.expiry)
	return rotated, err
}

// rejectDeadRefreshToken explains why a token could not be consumed. A revoked
// token being presented again means it leaked, so its whole family is revoked.
func rejectDeadRefreshToken(ctx context.Context, db *pgxpool.Pool, hash string) (int, error) {
	var revoked bool
	var familyID uuid.UUID
	err := db.QueryRow(ctx,
		"SELECT revoked, family_id FROM auth.refresh_tokens WHERE token_hash = $1", hash,
	).Scan(&revoked, &familyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 401, errInvalidRefreshToken
	}
	if err != nil {
		return 500, errRefreshTokenStore
	}
	if !revoked {
		return 401, errRefreshTokenExpired
	}
	if _, err := db.Exec(ctx,
		"UPDATE auth.refresh_tokens SET revoked = true WHERE family_id = $1 AND revoked = false", familyID,
	); err != nil {
		return 500, errRefreshTokenStore
	}
	log.Printf("auth.refresh.reuse family=%s revoked", familyID)
	return 401, errRefreshTokenRevoked
}
