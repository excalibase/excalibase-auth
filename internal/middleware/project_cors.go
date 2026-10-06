package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// ProjectOrigins resolves a project's browser-origin allowlist.
type ProjectOrigins interface {
	OriginsFor(ctx context.Context, projectID string) ([]string, error)
}

// corsWildcard is how provisioning stores "any origin": the list's only entry.
const corsWildcard = "*"

// ProjectCORS answers CORS on /{orgSlug}/{projectId} routes. It must be mounted
// inside that route so the project id is chi's own routing of the path.
//
//   - an explicit platform origin (Studio) is trusted as before, credentials included;
//   - otherwise the project's allowlist decides: an exact Origin match is
//     echoed, a lone "*" answers *, and neither carries credentials;
//   - an unknown project or an allowlist that cannot be read grants nothing,
//     and a refused preflight is a 403.
//
// A platform "*" is ignored here: it is not a project's decision.
func ProjectCORS(platformOrigins []string, origins ProjectOrigins) func(http.Handler) http.Handler {
	platform := make(map[string]bool, len(platformOrigins))
	for _, o := range platformOrigins {
		if o != corsWildcard {
			platform[o] = true
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Add("Vary", "Origin")

			allowOrigin, credentials := platformGrant(platform, origin)
			if allowOrigin == "" {
				allowOrigin = projectGrant(r, origins, origin)
			}
			if allowOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
				if credentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
			}

			if r.Method != http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			if allowOrigin == "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			setPreflightHeaders(w)
			w.WriteHeader(http.StatusNoContent)
		})
	}
}

func platformGrant(platform map[string]bool, origin string) (string, bool) {
	if platform[origin] {
		return origin, true
	}
	return "", false
}

// projectGrant is the Access-Control-Allow-Origin value the project's
// allowlist gives origin, or "".
func projectGrant(r *http.Request, origins ProjectOrigins, origin string) string {
	projectID := chi.URLParam(r, "projectId")
	if projectID == "" || origins == nil {
		return ""
	}
	listed, err := origins.OriginsFor(r.Context(), projectID)
	if err != nil {
		// The project id is request-derived; the access log carries the path.
		log.Printf("WARN: project CORS allowlist unavailable, refusing cross-origin access: %v", err)
		return ""
	}
	if len(listed) == 1 && listed[0] == corsWildcard {
		return corsWildcard
	}
	for _, entry := range listed {
		if entry == origin {
			return origin
		}
	}
	return ""
}

// ExceptPathPrefix applies mw to every request whose path is not under prefix.
func ExceptPathPrefix(prefix string, mw func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		wrapped := mw(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, prefix) {
				next.ServeHTTP(w, r)
				return
			}
			wrapped.ServeHTTP(w, r)
		})
	}
}
