package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/token"
	"github.com/go-chi/chi/v5"
)

func forgotPasswordRouter(t *testing.T, trusted []*net.IPNet) *chi.Mux {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := x509.MarshalECPrivateKey(priv)
	jwtSvc, _ := auth.NewJWTService(string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})), "excalibase", 3600)
	mgr := pool.NewManager("http://127.0.0.1:1", token.Literal("fake-pat"), time.Hour)
	h := NewAuthHandler(mgr, jwtSvc, 604800).WithTrustedProxies(trusted)
	r := chi.NewRouter()
	r.Route("/auth", h.Routes)
	return r
}

func forgotFrom(r *chi.Mux, remoteAddr, forwardedFor, address string) int {
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/forgot-password",
		strings.NewReader(fmt.Sprintf(`{"email":%q}`, address)))
	req.RemoteAddr = remoteAddr
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", forwardedFor)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

// A direct client cannot escape the per-IP cap by inventing X-Forwarded-For.
func TestForgotPassword_IgnoresForwardedForFromUntrustedPeer(t *testing.T) {
	r := forgotPasswordRouter(t, nil)
	for i := 1; i <= forgotPasswordLimit; i++ {
		address := fmt.Sprintf("victim%d@test.com", i)
		if code := forgotFrom(r, "198.51.100.7:4000", fmt.Sprintf("203.0.113.%d", i), address); code != 200 {
			t.Fatalf("attempt %d: got %d, want 200", i, code)
		}
	}
	if code := forgotFrom(r, "198.51.100.7:4000", "203.0.113.200", "another@test.com"); code != 429 {
		t.Errorf("rotated X-Forwarded-For from the same peer: got %d, want 429", code)
	}
}

// Behind a trusted proxy the forwarded client address is what gets counted.
func TestForgotPassword_HonoursForwardedForFromTrustedProxy(t *testing.T) {
	_, proxy, _ := net.ParseCIDR("10.0.0.0/8")
	r := forgotPasswordRouter(t, []*net.IPNet{proxy})
	for i := 1; i <= forgotPasswordLimit; i++ {
		address := fmt.Sprintf("user%d@test.com", i)
		if code := forgotFrom(r, "10.1.2.3:4000", "203.0.113.5", address); code != 200 {
			t.Fatalf("attempt %d: got %d, want 200", i, code)
		}
	}
	if code := forgotFrom(r, "10.1.2.3:4000", "203.0.113.6", "fresh@test.com"); code != 200 {
		t.Errorf("a different client behind the same proxy: got %d, want 200", code)
	}
	if code := forgotFrom(r, "10.1.2.3:4000", "203.0.113.5", "again@test.com"); code != 429 {
		t.Errorf("the capped client behind the proxy: got %d, want 429", code)
	}
}
