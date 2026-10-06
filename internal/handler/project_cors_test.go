package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/cors"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/token"
	"github.com/go-chi/chi/v5"
)

// The browser sign-in path end to end through the real router and the real
// provisioning-backed allowlist: a page on a project's app URL can exchange its
// publishable key, any other origin cannot.
func TestProjectRoutesAnswerCORSFromTheProjectsAllowlist(t *testing.T) {
	const appOrigin = "https://examples-jfp7kx46kb.apps.excalibase.io"
	provisioning := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/projects/proj-jfp7kx46kb/info":
			_, _ = w.Write([]byte(`{"projectId":"proj-jfp7kx46kb","corsAllowedOrigins":["` + appOrigin + `"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer provisioning.Close()

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(priv)
	jwtSvc, _ := auth.NewJWTService(string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), "excalibase", 3600)
	tokens := token.Literal("pat")
	h := NewAuthHandler(pool.NewManager(provisioning.URL, tokens, time.Hour), jwtSvc, 604800).
		WithCORS([]string{"https://app.excalibase.io"}, cors.NewProvisioningProvider(provisioning.URL, tokens, 30*time.Second))
	r := chi.NewRouter()
	r.Route("/auth", h.Routes)

	preflight := func(path, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodOptions, path, nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "content-type")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	for _, route := range []string{"token", "register", "login", "refresh", "logout", "forgot-password", "reset-password", "verify-email"} {
		path := "/auth/default/proj-jfp7kx46kb/" + route
		if w := preflight(path, appOrigin); w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != appOrigin {
			t.Errorf("%s: preflight %d Allow-Origin %q, want 204 %s", route, w.Code, w.Header().Get("Access-Control-Allow-Origin"), appOrigin)
		}
	}
	if w := preflight("/auth/default/proj-jfp7kx46kb/token", "https://evil.example.com"); w.Code != http.StatusForbidden {
		t.Errorf("unlisted origin: preflight %d, want 403", w.Code)
	}
	if w := preflight("/auth/default/proj-unknown/token", appOrigin); w.Code != http.StatusForbidden {
		t.Errorf("unknown project: preflight %d, want 403", w.Code)
	}

	// The actual POST carries the grant too, so the page can read the answer.
	req := httptest.NewRequest(http.MethodPost, "/auth/default/proj-jfp7kx46kb/token", strings.NewReader(`{"grant_type":"nope"}`))
	req.Header.Set("Origin", appOrigin)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != appOrigin {
		t.Errorf("POST Allow-Origin %q, want %s", got, appOrigin)
	}
}

// Without WithCORS the project routes grant no origin at all.
func TestProjectRoutesGrantNothingWithoutAnAllowlistSource(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(priv)
	jwtSvc, _ := auth.NewJWTService(string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), "excalibase", 3600)
	h := NewAuthHandler(pool.NewManager("http://127.0.0.1:1", token.Literal("pat"), time.Hour), jwtSvc, 604800)
	r := chi.NewRouter()
	r.Route("/auth", h.Routes)

	req := httptest.NewRequest(http.MethodOptions, "/auth/default/proj-1/token", nil)
	req.Header.Set("Origin", "https://shop.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin %q, want none", got)
	}
}
