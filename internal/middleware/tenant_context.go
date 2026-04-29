// Package middleware contains HTTP middleware shared across handlers.
//
// tenant_context.go propagates the per-request tenant identity (projectId and
// orgSlug extracted from the chi URL params) into the request context and
// request logs. Downstream handlers read the values via TenantIDFromContext /
// OrgSlugFromContext instead of re-parsing chi params, which keeps logging and
// future trace/metric enrichment uniform across the service.
package middleware

import (
	"context"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// contextKey is an unexported type so external packages cannot collide with
// our context keys.
type contextKey string

const (
	tenantIDKey contextKey = "tenant_id"
	orgSlugKey  contextKey = "org_slug"
)

// TenantContext attaches the chi-routed {projectId} and {orgSlug} to the
// request context and emits a single structured log line per request tagged
// with tenant + org. When the route does not match the tenant-scoped pattern
// (projectId empty), the middleware is a no-op and the request passes through
// untouched so it can be mounted broadly without side effects.
//
// TODO: OTEL SDK is not integrated in this service (only indirect deps via
// testcontainers). Once a real tracer provider is wired in, set span
// attributes `tenant.id` and `org.slug` here so traces inherit the same
// propagation.
func TenantContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		projectID := chi.URLParam(r, "projectId")
		orgSlug := chi.URLParam(r, "orgSlug")

		if projectID != "" {
			ctx := context.WithValue(r.Context(), tenantIDKey, projectID)
			ctx = context.WithValue(ctx, orgSlugKey, orgSlug)
			r = r.WithContext(ctx)

			log.Printf("tenant=%s org=%s path=%s method=%s", projectID, orgSlug, r.URL.Path, r.Method)
		}

		next.ServeHTTP(w, r)
	})
}

// TenantIDFromContext returns the projectId previously stored by
// TenantContext. The second return value reports whether the value was
// present, letting callers distinguish "absent" from "empty string".
func TenantIDFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(tenantIDKey).(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// OrgSlugFromContext returns the orgSlug previously stored by TenantContext.
// See TenantIDFromContext for the (value, present) contract.
func OrgSlugFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(orgSlugKey).(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}
