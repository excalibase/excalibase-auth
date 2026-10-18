package handler

import (
	"context"
	"errors"
	"time"

	"github.com/excalibase/auth/internal/store"
	"github.com/excalibase/auth/internal/token"
)

// errTokenNotRedeemable covers every reason a link can't be used — unknown,
// already consumed, or expired. The three are deliberately indistinguishable to
// the caller so a probe can't tell "never existed" from "already used".
var errTokenNotRedeemable = errors.New("invalid_or_expired_token")

// singleUseTokens are hashed, expiring, one-shot links of one kind; the store
// holds a fixed table per kind.
type singleUseTokens struct {
	kind store.TokenKind
}

var (
	emailVerificationTokens = singleUseTokens{kind: store.EmailVerification}
	passwordResetTokens     = singleUseTokens{kind: store.PasswordReset}
)

// issue invalidates any outstanding tokens for the user and mints a new one.
// Returns the plaintext, which exists only in the email that follows — the
// database holds nothing but its hash.
func (s singleUseTokens) issue(ctx context.Context, db store.Store, userID int64, ttl time.Duration, confirmsPassword bool) (string, error) {
	plaintext, hash, err := token.New()
	if err != nil {
		return "", err
	}
	if err := db.IssueToken(ctx, s.kind, userID, hash, time.Now().Add(ttl), confirmsPassword); err != nil {
		return "", err
	}
	return plaintext, nil
}

// redeem validates a plaintext token and marks it consumed, returning the user
// it belongs to. Returns errTokenNotRedeemable for unknown, expired, and
// already-used tokens alike; of concurrent redeems only one consumes it.
func (s singleUseTokens) redeem(ctx context.Context, db store.Store, plaintext string) (int64, error) {
	found, err := s.lookup(ctx, db, plaintext)
	if err != nil {
		return 0, err
	}
	if err := s.claim(ctx, db, found.RowID); err != nil {
		return 0, err
	}
	return found.UserID, nil
}

// claim consumes a looked-up token row; it fails if another request already did.
func (s singleUseTokens) claim(ctx context.Context, db store.Store, rowID int64) error {
	claimed, err := db.ClaimToken(ctx, s.kind, rowID)
	if err != nil || !claimed {
		return errTokenNotRedeemable
	}
	return nil
}

// peek reports the user a live token belongs to without consuming it.
func (s singleUseTokens) peek(ctx context.Context, db store.Store, plaintext string) (int64, error) {
	found, err := s.lookup(ctx, db, plaintext)
	return found.UserID, err
}

func (s singleUseTokens) lookup(ctx context.Context, db store.Store, plaintext string) (store.SingleUseToken, error) {
	if plaintext == "" {
		return store.SingleUseToken{}, errTokenNotRedeemable
	}
	hash := token.Hash(plaintext)
	found, err := db.LookupToken(ctx, s.kind, hash)
	if err != nil {
		return store.SingleUseToken{}, errTokenNotRedeemable
	}
	// The row was found by an equality match the database performed; repeat it
	// in constant time so the decisive comparison carries no timing signal.
	if !token.Equal(found.Hash, hash) {
		return store.SingleUseToken{}, errTokenNotRedeemable
	}
	return found, nil
}
