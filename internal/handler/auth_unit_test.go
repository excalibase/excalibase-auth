package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/token"
	"github.com/go-chi/chi/v5"
)

func setupUnitRouter(t *testing.T) chi.Router {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))

	jwtSvc, _ := auth.NewJWTService(keyPEM, "excalibase", 3600)
	// Pool manager with unreachable vault — all DB operations will fail
	mgr := pool.NewManager("http://127.0.0.1:1", token.Literal("fake-pat"), time.Hour)
	h := NewAuthHandler(mgr, jwtSvc, 604800)

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

// The token's real lifetime and the advertised expires_in must both be the
// signer's access TTL, for the password and api-key grants alike.
func TestAuthResponses_ExpMatchesAdvertisedTTL(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))
	const accessTTL = 900
	jwtSvc, _ := auth.NewJWTService(keyPEM, "excalibase", accessTTL)
	mgr := pool.NewManager("http://127.0.0.1:1", token.Literal("fake-pat"), time.Hour)
	h := NewAuthHandler(mgr, jwtSvc, 604800)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("orgSlug", "test-org")
	req := httptest.NewRequest("POST", "/", nil).WithContext(
		context.WithValue(context.Background(), chi.RouteCtxKey, rctx),
	)

	password, err := h.sessionResponse(req, "test-project", domain.UserInfo{ID: 42, Email: "alice@example.com"}, false, "refresh")
	if err != nil {
		t.Fatalf("sessionResponse: %v", err)
	}
	apiKey, err := h.generateAPIKeyAuthResponse(req, "test-project", 0, 7, "publishable")
	if err != nil {
		t.Fatalf("generateAPIKeyAuthResponse: %v", err)
	}
	for name, resp := range map[string]*domain.AuthResponse{"password": password, "api key": apiKey} {
		if resp.ExpiresIn != accessTTL {
			t.Errorf("%s expires_in: got %d, want %d", name, resp.ExpiresIn, accessTTL)
		}
		if lifetime := tokenLifetime(t, resp.AccessToken); lifetime != accessTTL {
			t.Errorf("%s exp - iat: got %d, want %d", name, lifetime, accessTTL)
		}
	}
}

func tokenLifetime(t *testing.T, tok string) int64 {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims struct {
		Exp int64 `json:"exp"`
		Iat int64 `json:"iat"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims.Exp - claims.Iat
}
