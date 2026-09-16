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
	"sync"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/middleware"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/ratelimit"
	"github.com/go-chi/chi/v5"
)

const (
	rlRegisterPath = "/auth/test-org/test-project/register"
	rlLoginPath    = "/auth/test-org/test-project/login"
	rlTokenPath    = "/auth/test-org/test-project/token"
	rlRefreshPath  = "/auth/test-org/test-project/refresh"
)

type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// setupRateLimitedRouter mirrors setupUnitRouter (unreachable vault, so every
// request that passes the limiter ends in 503/401) but wires the rate-limit
// middleware with a manual clock and tiny budgets.
func setupRateLimitedRouter(t *testing.T) (chi.Router, *manualClock) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))
	jwtSvc, _ := auth.NewJWTService(keyPEM, "excalibase", 3600)
	mgr := pool.NewManager("http://127.0.0.1:1", "fake-pat", time.Hour)

	clock := &manualClock{now: time.Unix(1_700_000_000, 0)}
	limits := middleware.NewRateLimits(middleware.RateLimitConfig{
		Window:             time.Minute,
		RegisterPerIP:      2,
		LoginPerIP:         2,
		TokenPerIP:         2,
		RegisterPerProject: 100,
		LoginFailures:      100,
		FailureWindow:      15 * time.Minute,
	}, ratelimit.WithClock(clock.Now))

	h := NewAuthHandler(mgr, jwtSvc, 900, 604800).WithRateLimits(limits)
	r := chi.NewRouter()
	r.Route("/auth", h.Routes)
	return r, clock
}

func postFrom(r http.Handler, path, ip, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":40000"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestRateLimit_RoutesReturn429ThenRecover(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
	}{
		{name: "register", path: rlRegisterPath, body: `{"email":"a@b.com","password":"pass1234","fullName":"Test"}`},
		{name: "login", path: rlLoginPath, body: `{"email":"a@b.com","password":"pass1234"}`},
		{name: "token", path: rlTokenPath, body: `{"grant_type":"refresh_token","refresh_token":"x"}`},
		{name: "refresh shares the token budget", path: rlRefreshPath, body: `{"refreshToken":"x"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, clock := setupRateLimitedRouter(t)
			for i := 0; i < 2; i++ {
				if w := postFrom(r, tt.path, "203.0.113.10", tt.body); w.Code == http.StatusTooManyRequests {
					t.Fatalf("request %d: limited too early", i+1)
				}
			}
			w := postFrom(r, tt.path, "203.0.113.10", tt.body)
			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("request 3: got %d, want 429", w.Code)
			}
			if w.Header().Get("Retry-After") == "" {
				t.Error("429 must carry Retry-After")
			}
			if !strings.Contains(w.Body.String(), `"error":"rate_limited"`) {
				t.Errorf("body: got %s", w.Body.String())
			}

			clock.Advance(time.Minute)
			if w := postFrom(r, tt.path, "203.0.113.10", tt.body); w.Code == http.StatusTooManyRequests {
				t.Fatal("must recover after the window")
			}
		})
	}
}

func TestRateLimit_RefreshAndTokenShareBudget(t *testing.T) {
	r, _ := setupRateLimitedRouter(t)
	postFrom(r, rlTokenPath, "203.0.113.11", `{"grant_type":"refresh_token","refresh_token":"x"}`)
	postFrom(r, rlRefreshPath, "203.0.113.11", `{"refreshToken":"x"}`)
	if w := postFrom(r, rlTokenPath, "203.0.113.11", `{"grant_type":"refresh_token","refresh_token":"x"}`); w.Code != http.StatusTooManyRequests {
		t.Fatalf("legacy /refresh must not be a way around the /token budget: got %d", w.Code)
	}
}

func TestRateLimit_NotWiredWhenNil(t *testing.T) {
	r := setupUnitRouter(t)
	body := `{"email":"a@b.com","password":"pass1234"}`
	for i := 0; i < 20; i++ {
		if w := postFrom(r, rlLoginPath, "203.0.113.12", body); w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d: handler without limits must never 429", i+1)
		}
	}
}

// A real successful login must clear the identity failure counter: four
// failures, one success, then four more failures must all be 401 (not 429),
// which is only possible if the success reset the budget of five.
func TestIntegration_RateLimit_LoginFailureCounterResetsOnSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	limits := middleware.NewRateLimits(middleware.RateLimitConfig{
		Window:             time.Minute,
		RegisterPerIP:      100,
		LoginPerIP:         100,
		TokenPerIP:         100,
		RegisterPerProject: 100,
		LoginFailures:      5,
		FailureWindow:      15 * time.Minute,
	})
	fx, cleanup := setupIntegrationFixture(t, func(h *AuthHandler) *AuthHandler { return h.WithRateLimits(limits) })
	defer cleanup()

	resp := postJSON(fx.srv, rlRegisterPath, map[string]string{
		"email": "lock@test.com", "password": "correct-horse", "fullName": "Lock",
	})
	if resp.StatusCode != 201 {
		t.Fatalf("register: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	login := func(password string) int {
		resp := postJSON(fx.srv, rlLoginPath, map[string]string{"email": "lock@test.com", "password": password})
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < 4; i++ {
		if got := login("wrong"); got != 401 {
			t.Fatalf("failure %d: got %d, want 401", i+1, got)
		}
	}
	if got := login("correct-horse"); got != 200 {
		t.Fatalf("successful login: got %d, want 200", got)
	}
	for i := 0; i < 4; i++ {
		if got := login("wrong"); got != 401 {
			t.Fatalf("failure %d after success: got %d, want 401 (counter reset)", i+1, got)
		}
	}
	if got := login("wrong"); got != 401 {
		t.Fatalf("5th failure after success: got %d, want 401", got)
	}
	if got := login("correct-horse"); got != 429 {
		t.Fatalf("6th attempt with the identity locked: got %d, want 429 even with the right password", got)
	}
}
