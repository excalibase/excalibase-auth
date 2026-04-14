package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/excalibase/auth/internal/auth"
)

func newTestJWT(t *testing.T) *auth.JWTService {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))
	jwtSvc, err := auth.NewJWTService(keyPEM, "test-issuer", 3600)
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}
	return jwtSvc
}

func TestRequireJWT_MissingHeader(t *testing.T) {
	jwtSvc := newTestJWT(t)
	called := false
	h := RequireJWT(jwtSvc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	req := httptest.NewRequest("GET", "/protected", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Errorf("missing Authorization: got %d, want 401", w.Code)
	}
	if called {
		t.Error("downstream handler must not run on auth failure")
	}
}

func TestRequireJWT_MissingBearerPrefix(t *testing.T) {
	jwtSvc := newTestJWT(t)
	h := RequireJWT(jwtSvc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "raw-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Errorf("missing Bearer prefix: got %d, want 401", w.Code)
	}
}

func TestRequireJWT_InvalidSignature(t *testing.T) {
	jwtSvc := newTestJWT(t)
	h := RequireJWT(jwtSvc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Errorf("invalid token: got %d, want 401", w.Code)
	}
}

func TestRequireJWT_ValidPassesThrough(t *testing.T) {
	jwtSvc := newTestJWT(t)
	tok, err := jwtSvc.Sign(auth.Claims{
		Sub:         "alice@test.com",
		UserID:      42,
		ProjectID:   "test-org/test-project",
		OrgSlug:     "test-org",
		ProjectName: "test-project",
		Role:        "user",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	called := false
	var seenClaims *auth.Claims
	h := RequireJWT(jwtSvc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		seenClaims = ClaimsFromContext(r.Context())
	}))
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("valid token: got %d, want 200", w.Code)
	}
	if !called {
		t.Error("downstream handler must run on valid token")
	}
	if seenClaims == nil {
		t.Fatal("ClaimsFromContext returned nil for valid token")
	}
	if seenClaims.UserID != 42 {
		t.Errorf("UserID: got %d, want 42", seenClaims.UserID)
	}
	if seenClaims.Sub != "alice@test.com" {
		t.Errorf("Sub: got %q, want alice@test.com", seenClaims.Sub)
	}
}
