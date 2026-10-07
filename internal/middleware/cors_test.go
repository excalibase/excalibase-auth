package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCORS_AllowedOrigin(t *testing.T) {
	handler := CORS([]string{"https://app.excalibase.io"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Origin", "https://app.excalibase.io")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://app.excalibase.io" {
		t.Errorf("Allow-Origin: got %q, want %q", got, "https://app.excalibase.io")
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Allow-Credentials: got %q, want %q", got, "true")
	}
}

func TestCORS_BlockedOrigin(t *testing.T) {
	handler := CORS([]string{"https://app.excalibase.io"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Origin", "https://evil.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin should be empty for blocked origin, got %q", got)
	}
}

func TestCORS_NoOriginHeader(t *testing.T) {
	handler := CORS([]string{"https://app.excalibase.io"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin should be empty when no Origin header, got %q", got)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestCORS_Preflight(t *testing.T) {
	handler := CORS([]string{"https://app.excalibase.io"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for preflight")
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/test", nil)
	req.Header.Set("Origin", "https://app.excalibase.io")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("preflight status: got %d, want %d", rr.Code, http.StatusNoContent)
	}
	if got := rr.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("preflight should include Allow-Methods")
	}
	if got := rr.Header().Get("Access-Control-Max-Age"); got != "3600" {
		t.Errorf("Max-Age: got %q, want %q", got, "3600")
	}
}

func TestCORS_PreflightBlockedOrigin(t *testing.T) {
	handler := CORS([]string{"https://app.excalibase.io"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/test", nil)
	req.Header.Set("Origin", "https://evil.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// A refused preflight is a 403 on every service (EXC-563), not a bare 204.
	if rr.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want %d", rr.Code, http.StatusForbidden)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin should be empty for blocked origin, got %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Methods"); got != "" {
		t.Errorf("Allow-Methods should be empty for blocked origin, got %q", got)
	}
}

// An actual request is served whatever its Origin; only a listed origin is
// granted, and every answer varies by Origin so a cache cannot replay one
// origin's answer to another.
func TestCORS_UnlistedOriginIsServedWithoutGrant(t *testing.T) {
	for _, origin := range []string{"https://evil.com", "capacitor://localhost", "null"} {
		reached := false
		handler := CORS([]string{"https://app.excalibase.io"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
		req.Header.Set("Origin", origin)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if !reached || rr.Code != http.StatusOK {
			t.Errorf("%s: status %d reached=%v, want served", origin, rr.Code, reached)
		}
		if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("%s: Allow-Origin = %q, want none", origin, got)
		}
		if got := rr.Header().Get("Vary"); got != "Origin" {
			t.Errorf("%s: Vary = %q, want Origin", origin, got)
		}
	}
}

func TestCORS_MultipleOrigins(t *testing.T) {
	origins := []string{"https://app.excalibase.io", "http://localhost:3000"}
	handler := CORS(origins)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name   string
		origin string
		want   string
	}{
		{"app origin", "https://app.excalibase.io", "https://app.excalibase.io"},
		{"localhost origin", "http://localhost:3000", "http://localhost:3000"},
		{"blocked origin", "https://evil.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			req.Header.Set("Origin", tt.origin)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if got := rr.Header().Get("Access-Control-Allow-Origin"); got != tt.want {
				t.Errorf("Allow-Origin: got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCORS_WildcardAllowsAll(t *testing.T) {
	handler := CORS([]string{"*"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Origin", "https://anything.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://anything.com" {
		t.Errorf("Allow-Origin: got %q, want %q", got, "https://anything.com")
	}
}

func TestCORS_VaryHeader(t *testing.T) {
	handler := CORS([]string{"https://app.excalibase.io"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Origin", "https://app.excalibase.io")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary: got %q, want %q", got, "Origin")
	}
}

// @excalibase/sdk sends its publishable key header on every auth call, and a
// role header may ride along; a browser app on its own origin must get past the
// preflight with them, or it can never sign in.
func TestCORS_PreflightAllowsTheSDKHeaders(t *testing.T) {
	handler := CORS([]string{"*"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for preflight")
	}))

	req := httptest.NewRequest(http.MethodOptions, "/auth/acme/proj-1/token", nil)
	req.Header.Set("Origin", "https://shop.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type,x-excalibase-publishable-key,x-excalibase-role")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	allowed := strings.ToLower(rr.Header().Get("Access-Control-Allow-Headers"))
	for _, header := range []string{"authorization", "content-type", "x-excalibase-publishable-key", "x-excalibase-role"} {
		if !strings.Contains(allowed, header) {
			t.Errorf("Allow-Headers %q is missing %s", allowed, header)
		}
	}
}
