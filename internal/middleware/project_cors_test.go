package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// fakeOrigins is a per-project allowlist keyed by project id; a missing
// project answers err, like an unknown project or a provisioning outage.
type fakeOrigins struct {
	lists map[string][]string
	err   error
	asked []string
}

func (f *fakeOrigins) OriginsFor(_ context.Context, projectID string) ([]string, error) {
	f.asked = append(f.asked, projectID)
	if list, ok := f.lists[projectID]; ok {
		return list, nil
	}
	if f.err != nil {
		return nil, f.err
	}
	return nil, errors.New("unknown project")
}

const (
	studioOrigin = "https://app.excalibase.io"
	appOrigin    = "https://examples-jfp7kx46kb.apps.excalibase.io"
)

// projectRouter mounts ProjectCORS the way AuthHandler.Routes does, so the
// project id comes from chi's own routing of /auth/{orgSlug}/{projectId}.
func projectRouter(t *testing.T, platform []string, origins ProjectOrigins) (http.Handler, *bool) {
	t.Helper()
	reached := false
	r := chi.NewRouter()
	r.Route("/auth/{orgSlug}/{projectId}", func(r chi.Router) {
		r.Use(ProjectCORS(platform, origins))
		r.Post("/token", func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		})
	})
	return r, &reached
}

func send(h http.Handler, method, path, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if method == http.MethodOptions {
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "content-type,x-excalibase-publishable-key")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

const tokenPath = "/auth/default/proj-jfp7kx46kb/token"

func TestProjectCORSAllowsAnOriginOnTheProjectsAllowlist(t *testing.T) {
	origins := &fakeOrigins{lists: map[string][]string{"proj-jfp7kx46kb": {appOrigin}}}
	h, reached := projectRouter(t, []string{studioOrigin}, origins)

	rr := send(h, http.MethodPost, tokenPath, appOrigin)

	if rr.Code != http.StatusOK || !*reached {
		t.Fatalf("status %d reached=%v, want the request served", rr.Code, *reached)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != appOrigin {
		t.Errorf("Allow-Origin = %q, want %q", got, appOrigin)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("Allow-Credentials = %q, want none for a project origin", got)
	}
	if got := rr.Header().Values("Vary"); len(got) != 1 || got[0] != "Origin" {
		t.Errorf("Vary = %v, want [Origin]", got)
	}
	if len(origins.asked) != 1 || origins.asked[0] != "proj-jfp7kx46kb" {
		t.Errorf("allowlist looked up for %v, want [proj-jfp7kx46kb]", origins.asked)
	}
}

func TestProjectCORSPreflightForAnAllowedOrigin(t *testing.T) {
	origins := &fakeOrigins{lists: map[string][]string{"proj-jfp7kx46kb": {appOrigin}}}
	h, reached := projectRouter(t, []string{studioOrigin}, origins)

	rr := send(h, http.MethodOptions, tokenPath, appOrigin)

	if rr.Code != http.StatusNoContent || *reached {
		t.Fatalf("status %d reached=%v, want 204 answered by the middleware", rr.Code, *reached)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != appOrigin {
		t.Errorf("Allow-Origin = %q", got)
	}
	if rr.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("preflight is missing Allow-Methods")
	}
	allowed := strings.ToLower(rr.Header().Get("Access-Control-Allow-Headers"))
	for _, header := range []string{"authorization", "content-type", "x-excalibase-publishable-key", "x-excalibase-role"} {
		if !strings.Contains(allowed, header) {
			t.Errorf("Allow-Headers %q is missing %s", allowed, header)
		}
	}
	if got := rr.Header().Get("Access-Control-Max-Age"); got != "3600" {
		t.Errorf("Max-Age = %q", got)
	}
}

func TestProjectCORSRefusesAnOriginNotOnTheAllowlist(t *testing.T) {
	origins := &fakeOrigins{lists: map[string][]string{"proj-jfp7kx46kb": {appOrigin}}}
	h, _ := projectRouter(t, []string{studioOrigin}, origins)

	for _, origin := range []string{
		"https://evil.example.com",
		"http://examples-jfp7kx46kb.apps.excalibase.io",       // scheme differs
		"https://examples-jfp7kx46kb.apps.excalibase.io:8443", // port differs
		"https://examples-jfp7kx46kb.apps.excalibase.io.evil.com",
		"null",
	} {
		rr := send(h, http.MethodPost, tokenPath, origin)
		if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("%s: Allow-Origin = %q, want none", origin, got)
		}
		if got := rr.Header().Get("Vary"); got != "Origin" {
			t.Errorf("%s: Vary = %q, want Origin", origin, got)
		}

		pre := send(h, http.MethodOptions, tokenPath, origin)
		if pre.Code != http.StatusForbidden {
			t.Errorf("%s: preflight status %d, want 403", origin, pre.Code)
		}
		if got := pre.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("%s: preflight Allow-Origin = %q, want none", origin, got)
		}
	}
}

// One project's allowlist never opens another project's routes.
func TestProjectCORSUsesTheAllowlistOfTheProjectInThePath(t *testing.T) {
	origins := &fakeOrigins{lists: map[string][]string{
		"proj-a": {appOrigin},
		"proj-b": {"https://other.example.com"},
	}}
	h, _ := projectRouter(t, []string{studioOrigin}, origins)

	rr := send(h, http.MethodOptions, "/auth/default/proj-b/token", appOrigin)
	if rr.Code != http.StatusForbidden || rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("proj-a's origin on proj-b: status %d Allow-Origin %q, want refused", rr.Code, rr.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestProjectCORSRefusesAnUnknownProject(t *testing.T) {
	origins := &fakeOrigins{lists: map[string][]string{}}
	h, _ := projectRouter(t, []string{studioOrigin}, origins)

	rr := send(h, http.MethodOptions, "/auth/default/proj-missing/token", appOrigin)
	if rr.Code != http.StatusForbidden || rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("status %d Allow-Origin %q, want refused", rr.Code, rr.Header().Get("Access-Control-Allow-Origin"))
	}
}

// Fail closed: an allowlist that cannot be fetched refuses the cross-origin
// request; it never falls back to * or to reflecting the origin.
func TestProjectCORSRefusesWhenTheAllowlistCannotBeFetched(t *testing.T) {
	origins := &fakeOrigins{err: errors.New("provisioning unreachable")}
	h, reached := projectRouter(t, []string{studioOrigin}, origins)

	rr := send(h, http.MethodPost, tokenPath, appOrigin)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q, want none", got)
	}
	// CORS binds the browser, not the server: the request itself still runs and
	// the browser withholds the response from the page.
	if !*reached {
		t.Error("a non-preflight request should still reach the handler")
	}

	pre := send(h, http.MethodOptions, tokenPath, appOrigin)
	if pre.Code != http.StatusForbidden {
		t.Errorf("preflight status %d, want 403", pre.Code)
	}
}

func TestProjectCORSHonoursAStoredWildcardWithoutCredentials(t *testing.T) {
	origins := &fakeOrigins{lists: map[string][]string{"proj-jfp7kx46kb": {"*"}}}
	h, _ := projectRouter(t, []string{studioOrigin}, origins)

	rr := send(h, http.MethodOptions, tokenPath, "https://anyone.example.com")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status %d, want 204", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Allow-Origin = %q, want *", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("Allow-Credentials = %q, want none", got)
	}
}

// A * that is not the only entry is not the wildcard provisioning stores.
func TestProjectCORSIgnoresAStarNextToOtherEntries(t *testing.T) {
	origins := &fakeOrigins{lists: map[string][]string{"proj-jfp7kx46kb": {appOrigin, "*"}}}
	h, _ := projectRouter(t, []string{studioOrigin}, origins)

	rr := send(h, http.MethodOptions, tokenPath, "https://anyone.example.com")
	if rr.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403", rr.Code)
	}
}

// Studio keeps working on project routes exactly as before: trusted without a
// lookup, credentials included.
func TestProjectCORSKeepsStudioTrusted(t *testing.T) {
	origins := &fakeOrigins{err: errors.New("provisioning unreachable")}
	h, _ := projectRouter(t, []string{studioOrigin}, origins)

	rr := send(h, http.MethodOptions, tokenPath, studioOrigin)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status %d, want 204", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != studioOrigin {
		t.Errorf("Allow-Origin = %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Allow-Credentials = %q, want true", got)
	}
	if len(origins.asked) != 0 {
		t.Errorf("Studio's origin triggered an allowlist lookup for %v", origins.asked)
	}
}

// A platform CORS_ORIGINS of * (the AIO default) is not a project allowlist:
// on project routes only the project decides.
func TestProjectCORSDoesNotLetAPlatformWildcardOpenProjectRoutes(t *testing.T) {
	origins := &fakeOrigins{lists: map[string][]string{"proj-jfp7kx46kb": {}}}
	h, _ := projectRouter(t, []string{"*"}, origins)

	rr := send(h, http.MethodOptions, tokenPath, appOrigin)
	if rr.Code != http.StatusForbidden || rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("status %d Allow-Origin %q, want refused", rr.Code, rr.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestProjectCORSLeavesRequestsWithoutAnOriginAlone(t *testing.T) {
	origins := &fakeOrigins{}
	h, reached := projectRouter(t, []string{studioOrigin}, origins)

	rr := send(h, http.MethodPost, tokenPath, "")
	if rr.Code != http.StatusOK || !*reached {
		t.Errorf("status %d reached=%v, want served", rr.Code, *reached)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "" || len(origins.asked) != 0 {
		t.Errorf("a request without Origin got CORS handling")
	}
}

func TestExceptPathPrefixSkipsTheWrappedMiddlewareUnderThePrefix(t *testing.T) {
	marker := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Wrapped", "yes")
			next.ServeHTTP(w, r)
		})
	}
	h := ExceptPathPrefix("/auth/", marker)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for path, want := range map[string]string{"/healthz": "yes", "/.well-known/jwks.json": "yes", "/auth/default/p/token": "", "/authx": "yes"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if got := rr.Header().Get("X-Wrapped"); got != want {
			t.Errorf("%s: wrapped=%q, want %q", path, got, want)
		}
	}
}
