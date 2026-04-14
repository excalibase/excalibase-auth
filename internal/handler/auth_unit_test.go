package handler

import (
	"context"
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
	"github.com/excalibase/auth/internal/pool"
	"github.com/go-chi/chi/v5"
)

func setupUnitRouter(t *testing.T) chi.Router {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))

	jwtSvc, _ := auth.NewJWTService(keyPEM, "excalibase", 3600)
	// Pool manager with unreachable vault — all DB operations will fail
	mgr := pool.NewManager("http://127.0.0.1:1", "fake-pat", time.Hour)
	h := NewAuthHandler(mgr, jwtSvc, 900, 604800)

	r := chi.NewRouter()
	r.Route("/auth", h.Routes)
	return r
}

func TestRegister_BadJSON(t *testing.T) {
	r := setupUnitRouter(t)
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/register", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRegister_MissingFields(t *testing.T) {
	r := setupUnitRouter(t)
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/register", strings.NewReader(`{"email":"a@b.com"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Errorf("expected 400 for missing fields, got %d", w.Code)
	}
}

func TestRegister_DBUnavailable(t *testing.T) {
	r := setupUnitRouter(t)
	body := `{"email":"a@b.com","password":"pass1234","fullName":"Test"}`
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 503 {
		t.Errorf("expected 503 for DB unavailable, got %d", w.Code)
	}
}

func TestLogin_BadJSON(t *testing.T) {
	r := setupUnitRouter(t)
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/login", strings.NewReader("{bad"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestLogin_DBUnavailable(t *testing.T) {
	r := setupUnitRouter(t)
	body := `{"email":"a@b.com","password":"pass"}`
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	// Should be 503 (can't connect) or 401 (user not found after connect fails)
	if w.Code != 503 && w.Code != 401 {
		t.Errorf("expected 503 or 401, got %d", w.Code)
	}
}

func TestValidate_BadJSON(t *testing.T) {
	r := setupUnitRouter(t)
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/validate", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRefresh_BadJSON(t *testing.T) {
	r := setupUnitRouter(t)
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/refresh", strings.NewReader("xxx"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRefresh_DBUnavailable(t *testing.T) {
	r := setupUnitRouter(t)
	body := `{"refreshToken":"some-uuid"}`
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 503 && w.Code != 401 {
		t.Errorf("expected 503 or 401, got %d", w.Code)
	}
}

func TestLogout_BadJSON(t *testing.T) {
	r := setupUnitRouter(t)
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/logout", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestLogout_DBUnavailable(t *testing.T) {
	r := setupUnitRouter(t)
	body := `{"refreshToken":"some-uuid"}`
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/logout", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	// Logout with unreachable DB — 503
	if w.Code != 503 && w.Code != 200 {
		t.Errorf("expected 503 or 200, got %d", w.Code)
	}
}

func TestValidate_InvalidToken(t *testing.T) {
	r := setupUnitRouter(t)
	body := `{"token":"invalid.token.here"}`
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/validate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// generateAuthResponse must surface the configured access TTL, not the historical
// hardcoded 3600. This is a direct unit test of the private helper; the pool fetch
// is allowed to fail silently (refresh_tokens insert is skipped when pool==nil).
func TestGenerateAuthResponse_ExpiresInMatchesConfig(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))
	jwtSvc, _ := auth.NewJWTService(keyPEM, "excalibase", 3600)
	mgr := pool.NewManager("http://127.0.0.1:1", "fake-pat", time.Hour)

	const wantAccess = 900
	h := NewAuthHandler(mgr, jwtSvc, wantAccess, 604800)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("orgSlug", "test-org")
	rctx.URLParams.Add("projectName", "test-project")
	req := httptest.NewRequest("POST", "/", nil).WithContext(
		context.WithValue(context.Background(), chi.RouteCtxKey, rctx),
	)

	resp, err := h.generateAuthResponse(req, "test-org/test-project", 42, "alice@example.com", "Alice")
	if err != nil {
		t.Fatalf("generateAuthResponse: %v", err)
	}
	if resp.ExpiresIn != int64(wantAccess) {
		t.Errorf("ExpiresIn: got %d, want %d", resp.ExpiresIn, wantAccess)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType: got %s, want Bearer", resp.TokenType)
	}
	if resp.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}
}
