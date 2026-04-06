package middleware

import (
	"net/http"
	"strings"
)

// CORS returns middleware that validates Origin against allowed origins
// and sets appropriate CORS response headers.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	wildcard := len(allowedOrigins) == 1 && allowedOrigins[0] == "*"
	originSet := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		originSet[o] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			if origin != "" {
				allowed := wildcard || originSet[origin]
				if allowed {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Credentials", "true")
					w.Header().Set("Vary", "Origin")
				}
			}

			// Handle preflight
			if r.Method == http.MethodOptions {
				if origin != "" && (wildcard || originSet[origin]) {
					w.Header().Set("Access-Control-Allow-Methods", strings.Join([]string{
						"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH",
					}, ", "))
					w.Header().Set("Access-Control-Allow-Headers", strings.Join([]string{
						"Authorization", "Content-Type", "X-Request-ID", "X-CSRF-Token",
					}, ", "))
					w.Header().Set("Access-Control-Max-Age", "3600")
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
