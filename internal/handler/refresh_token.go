package handler

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/excalibase/auth/internal/store"
	"github.com/excalibase/auth/internal/token"
	"github.com/google/uuid"
)

var errRefreshTokenStore = errors.New("failed to store refresh token")

// newRefreshSession starts one login: every token rotated from it shares the
// family and the expiry, so rotation can neither outlive the login nor hide a replay.
func (h *AuthHandler) newRefreshSession() store.RefreshSession {
	return store.RefreshSession{
		FamilyID: uuid.New(),
		Expiry:   time.Now().Add(time.Duration(h.refreshExp) * time.Second),
	}
}

// storeRefreshToken mints a token in the session and persists only its hash.
func storeRefreshToken(ctx context.Context, db store.Store, userID int64, session store.RefreshSession) (string, error) {
	plaintext, hash, err := token.New()
	if err != nil {
		return "", err
	}
	if err := db.InsertRefreshToken(ctx, hash, userID, session); err != nil {
		return "", err
	}
	return plaintext, nil
}

// rejectDeadRefreshToken explains why a token could not be consumed. A revoked
// token being presented again means it leaked, so its whole family is revoked.
func rejectDeadRefreshToken(ctx context.Context, db store.Store, hash string) (int, error) {
	state, err := db.RefreshTokenState(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return 401, errInvalidRefreshToken
	}
	if err != nil {
		return 500, errRefreshTokenStore
	}
	if !state.Revoked {
		return 401, errRefreshTokenExpired
	}
	if err := db.RevokeRefreshFamily(ctx, state.FamilyID); err != nil {
		return 500, errRefreshTokenStore
	}
	log.Printf("auth.refresh.reuse family=%s revoked", state.FamilyID)
	return 401, errRefreshTokenRevoked
}
