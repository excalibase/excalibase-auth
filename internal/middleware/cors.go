package middleware

import (
	"net/http"
	"strings"
)

// CORS answers browser CORS on the platform routes (health, JWKS). As on every
// data-plane service (EXC-563) an actual request is never refused for its
// Origin: auth is a bearer token, so the browser enforces CORS by withholding
// an ungranted response. Only a listed origin is granted; an unlisted origin's
// preflight is a 403 without CORS headers.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	wildcard := len(allowedOrigins) == 1 && allowedOrigins[0] == "*"
	originSet := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		originSet[o] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			allowed := origin != "" && (wildcard || originSet[origin])
			if origin != "" {
				w.Header().Add("Vary", "Origin")
			}
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			if r.Method != http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			if origin != "" && !allowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if allowed {
				setPreflightHeaders(w)
			}
			w.WriteHeader(http.StatusNoContent)
		})
	}
}

// setPreflightHeaders grants the methods and headers a browser may use. The SDK
// sends its publishable key and may send a role on every call; a browser app
// cannot sign in unless both pass.
func setPreflightHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Methods", strings.Join([]string{
		"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH",
	}, ", "))
	w.Header().Set("Access-Control-Allow-Headers", strings.Join([]string{
		"Authorization", "Content-Type", "X-Request-ID", "X-CSRF-Token",
		"X-Excalibase-Publishable-Key", "X-Excalibase-Role",
	}, ", "))
	w.Header().Set("Access-Control-Max-Age", "3600")
}
