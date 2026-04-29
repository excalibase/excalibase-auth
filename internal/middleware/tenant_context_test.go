package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// mountTenantContext wraps TenantContext in a chi router that owns the
// {orgSlug}/{projectId} params so tests exercise the real URL param flow
// rather than faking the chi route context by hand.
func mountTenantContext(t *testing.T, onHit http.HandlerFunc) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	r.Route("/auth/{orgSlug}/{projectId}", func(r chi.Router) {
		r.Use(TenantContext)
		r.Get("/*", onHit)
	})
	r.Get("/*", onHit)
	return r
}

func TestTenantContext_ExtractsFromChiParams(t *testing.T) {
	var seenTenant, seenOrg string
	var tenantOK, orgOK bool
	h := mountTenantContext(t, func(w http.ResponseWriter, r *http.Request) {
		seenTenant, tenantOK = TenantIDFromContext(r.Context())
		seenOrg, orgOK = OrgSlugFromContext(r.Context())
	})

	req := httptest.NewRequest("GET", "/auth/acme-org/proj_abc123/register", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if !tenantOK {
		t.Fatal("TenantIDFromContext ok=false, want true for matched route")
	}
	if seenTenant != "proj_abc123" {
		t.Errorf("tenant: got %q, want %q", seenTenant, "proj_abc123")
	}
	if !orgOK {
		t.Fatal("OrgSlugFromContext ok=false, want true for matched route")
	}
	if seenOrg != "acme-org" {
		t.Errorf("org: got %q, want %q", seenOrg, "acme-org")
	}
}

func TestTenantContext_AbsentWhenRouteDoesNotMatch(t *testing.T) {
	var tenantOK, orgOK bool
	var seenTenant, seenOrg string
	// A plain http.Handler, no chi params at all — emulates the middleware
	// being run outside the tenant-scoped route group.
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenTenant, tenantOK = TenantIDFromContext(r.Context())
		seenOrg, orgOK = OrgSlugFromContext(r.Context())
	})
	wrapped := TenantContext(h)

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	if tenantOK || seenTenant != "" {
		t.Errorf("tenant: got (%q, %v), want (\"\", false)", seenTenant, tenantOK)
	}
	if orgOK || seenOrg != "" {
		t.Errorf("org: got (%q, %v), want (\"\", false)", seenOrg, orgOK)
	}
}

func TestTenantContext_DoesNotBlockRequest(t *testing.T) {
	called := false
	h := mountTenantContext(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest("GET", "/auth/acme-org/proj_abc123/whatever", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if !called {
		t.Error("downstream handler must run — TenantContext is observational, not gating")
	}
	if w.Code != http.StatusNoContent {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusNoContent)
	}
}

func TestTenantIDFromContext_EmptyContext(t *testing.T) {
	// Safety check: the helpers must tolerate a bare context with no values.
	req := httptest.NewRequest("GET", "/", nil)
	if v, ok := TenantIDFromContext(req.Context()); ok || v != "" {
		t.Errorf("bare ctx tenant: got (%q, %v), want (\"\", false)", v, ok)
	}
	if v, ok := OrgSlugFromContext(req.Context()); ok || v != "" {
		t.Errorf("bare ctx org: got (%q, %v), want (\"\", false)", v, ok)
	}
}
