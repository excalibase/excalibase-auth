package handler

import (
	"encoding/json"
	"net/http"

	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/middleware"
	"github.com/excalibase/auth/internal/token"
)

// Sign-out scopes: this session (the default), every other one, or all.
const (
	scopeLocal  = "local"
	scopeOthers = "others"
	scopeGlobal = "global"

	codeInvalidScope = "invalid_scope"
	loggedOutMessage = "Logged out successfully"
)

// Logout ends the presented session. scope=global ends every session of the
// signed-in caller and scope=others every one but the presented session;
// both need the caller's access token and account self-service on.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req domain.RefreshRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxOTPBody)).Decode(&req); err != nil {
		httpError(w, "invalid request", 400)
		return
	}
	switch scope := r.URL.Query().Get("scope"); scope {
	case "", scopeLocal:
		h.logoutLocal(w, r, req.RefreshToken)
	case scopeOthers, scopeGlobal:
		scoped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.logoutScoped(w, r, scope, req.RefreshToken) })
		h.requireUserAPI(middleware.RequireJWT(h.jwtService)(requireEndUser(scoped))).ServeHTTP(w, r)
	default:
		httpError(w, codeInvalidScope, http.StatusBadRequest)
	}
}

func (h *AuthHandler) logoutLocal(w http.ResponseWriter, r *http.Request, refreshToken string) {
	db, ok := h.storeFor(w, r)
	if !ok {
		return
	}
	if err := db.RevokeRefreshToken(r.Context(), token.Hash(refreshToken)); err != nil {
		httpError(w, "failed to log out", 500)
		return
	}
	writeJSON(w, map[string]string{"message": loggedOutMessage})
}

func (h *AuthHandler) logoutScoped(w http.ResponseWriter, r *http.Request, scope, refreshToken string) {
	db, ok := h.storeFor(w, r)
	if !ok {
		return
	}
	userID := middleware.ClaimsFromContext(r.Context()).UserID
	var err error
	if scope == scopeGlobal {
		err = db.RevokeUserRefreshTokens(r.Context(), userID)
	} else {
		state, lookupErr := db.RefreshTokenState(r.Context(), token.Hash(refreshToken))
		if lookupErr != nil || state.Revoked || state.UserID != userID {
			httpError(w, errInvalidRefreshToken.Error(), http.StatusBadRequest)
			return
		}
		err = db.RevokeOtherSessions(r.Context(), userID, state.FamilyID)
	}
	if err != nil {
		httpError(w, "failed to log out", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"message": loggedOutMessage})
}
