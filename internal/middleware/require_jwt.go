// Package middleware contains HTTP middleware shared across handlers.
//
// require_jwt.go enforces a valid bearer JWT on routes that need it (most
// notably the api-key CRUD endpoints). The verified Claims are stored in the
// request context so downstream handlers can read them via ClaimsFromContext.
package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/excalibase/auth/internal/auth"
)

type ctxKey int

const claimsCtxKey ctxKey = iota

// RequireJWT returns middleware that rejects requests without a valid Bearer
// token, surfacing 401 with a JSON error body. On success the verified
// *auth.Claims is attached to the request context.
func RequireJWT(jwtSvc *auth.JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeUnauthorized(w, "missing Authorization header")
				return
			}
			const prefix = "Bearer "
			if !strings.HasPrefix(authHeader, prefix) {
				writeUnauthorized(w, "Authorization header must be a Bearer token")
				return
			}
			token := strings.TrimPrefix(authHeader, prefix)
			claims, err := jwtSvc.Verify(token)
			if err != nil {
				writeUnauthorized(w, "invalid or expired token")
				return
			}
			ctx := context.WithValue(r.Context(), claimsCtxKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFromContext returns the *auth.Claims previously stored by RequireJWT,
// or nil if the request did not pass through the middleware.
func ClaimsFromContext(ctx context.Context) *auth.Claims {
	v, _ := ctx.Value(claimsCtxKey).(*auth.Claims)
	return v
}

func writeUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":  msg,
		"status": http.StatusUnauthorized,
	})
}
