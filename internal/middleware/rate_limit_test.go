package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/config"
	"github.com/excalibase/auth/internal/metrics"
	"github.com/excalibase/auth/internal/ratelimit"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const (
	testRegisterPath = "/auth/org/proj/register"
	testLoginPath    = "/auth/org/proj/login"
	testTokenPath    = "/auth/org/proj/token"
	loginBody        = `{"email":"alice@example.com","password":"x"}`
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func testConfig() RateLimitConfig {
	return RateLimitConfig{
		Window:             time.Minute,
		RegisterPerIP:      2,
		LoginPerIP:         3,
		TokenPerIP:         4,
		RegisterPerProject: 3,
		LoginFailures:      2,
		FailureWindow:      15 * time.Minute,
	}
}

// statusHandler echoes a fixed status so tests can simulate login outcomes.
func statusHandler(code int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
	})
}

func newTestRouter(cfg RateLimitConfig, clock *fakeClock, loginStatus int) chi.Router {
	limits := NewRateLimits(cfg, ratelimit.WithClock(clock.Now))
	r := chi.NewRouter()
	r.Route("/auth/{orgSlug}/{projectId}", func(r chi.Router) {
		r.With(limits.Register).Post("/register", statusHandler(http.StatusCreated).ServeHTTP)
		r.With(limits.Login).Post("/login", statusHandler(loginStatus).ServeHTTP)
		r.With(limits.Token).Post("/token", statusHandler(loginStatus).ServeHTTP)
	})
	return r
}

func post(r http.Handler, path, ip, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.RemoteAddr = ip + ":1234"
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}

func TestRateLimit_PerIPThresholds(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		limit int
	}{
		{name: "register", path: testRegisterPath, limit: 2},
		{name: "login", path: testLoginPath, limit: 3},
		{name: "token", path: testTokenPath, limit: 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
			r := newTestRouter(testConfig(), clock, http.StatusOK)

			for i := 0; i < tt.limit; i++ {
				if rr := post(r, tt.path, "203.0.113.1", loginBody); rr.Code == http.StatusTooManyRequests {
					t.Fatalf("request %d: unexpectedly limited", i+1)
				}
			}
			rr := post(r, tt.path, "203.0.113.1", loginBody)
			if rr.Code != http.StatusTooManyRequests {
				t.Fatalf("request %d: got %d, want 429", tt.limit+1, rr.Code)
			}
			assertRateLimitedResponse(t, rr)

			if rr := post(r, tt.path, "203.0.113.2", loginBody); rr.Code == http.StatusTooManyRequests {
				t.Fatal("other IP must not share the budget")
			}

			clock.Advance(time.Minute)
			if rr := post(r, tt.path, "203.0.113.1", loginBody); rr.Code == http.StatusTooManyRequests {
				t.Fatal("budget must recover after the window")
			}
		})
	}
}

func assertRateLimitedResponse(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	var body struct {
		Error      string `json:"error"`
		RetryAfter int    `json:"retryAfter"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("429 body is not JSON: %v", err)
	}
	if body.Error != "rate_limited" {
		t.Errorf("error: got %q, want rate_limited", body.Error)
	}
	if body.RetryAfter < 1 {
		t.Errorf("retryAfter: got %d, want >= 1", body.RetryAfter)
	}
	if got := rr.Header().Get("Retry-After"); got == "" || got == "0" {
		t.Errorf("Retry-After header: got %q, want positive seconds", got)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type: got %q", ct)
	}
}

func TestRateLimit_RegisterPerProject(t *testing.T) {
	cfg := testConfig()
	cfg.RegisterPerIP = 100
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	r := newTestRouter(cfg, clock, http.StatusOK)

	for i := 0; i < 3; i++ {
		ip := "203.0.113." + string(rune('1'+i))
		if rr := post(r, testRegisterPath, ip, loginBody); rr.Code != http.StatusCreated {
			t.Fatalf("register %d: got %d", i+1, rr.Code)
		}
	}
	if rr := post(r, testRegisterPath, "203.0.113.9", loginBody); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("4th register across IPs: got %d, want 429 (project cap)", rr.Code)
	}
	if rr := post(r, "/auth/org/other/register", "203.0.113.9", loginBody); rr.Code != http.StatusCreated {
		t.Fatalf("other project must have its own cap: got %d", rr.Code)
	}
}

func TestRateLimit_LoginFailuresLockIdentity(t *testing.T) {
	cfg := testConfig()
	cfg.LoginPerIP = 100
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	r := newTestRouter(cfg, clock, http.StatusUnauthorized)

	for i := 0; i < 2; i++ {
		if rr := post(r, testLoginPath, "203.0.113.1", loginBody); rr.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: got %d, want 401", i+1, rr.Code)
		}
	}
	rr := post(r, testLoginPath, "203.0.113.5", loginBody)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd attempt from another IP: got %d, want 429 (identity lock)", rr.Code)
	}
	assertRateLimitedResponse(t, rr)

	other := `{"email":"bob@example.com","password":"x"}`
	if rr := post(r, testLoginPath, "203.0.113.1", other); rr.Code != http.StatusUnauthorized {
		t.Fatalf("other identity must not be locked: got %d", rr.Code)
	}

	clock.Advance(15 * time.Minute)
	if rr := post(r, testLoginPath, "203.0.113.1", loginBody); rr.Code != http.StatusUnauthorized {
		t.Fatalf("after failure window: got %d, want 401 (unlocked)", rr.Code)
	}
}

func TestRateLimit_LoginFailureCounterResetsOnSuccess(t *testing.T) {
	cfg := testConfig()
	cfg.LoginPerIP = 100
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	limits := NewRateLimits(cfg, ratelimit.WithClock(clock.Now))

	var status int
	r := chi.NewRouter()
	r.With(limits.Login).Post("/auth/{orgSlug}/{projectId}/login", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	})

	status = http.StatusUnauthorized
	post(r, testLoginPath, "203.0.113.1", loginBody)
	status = http.StatusOK
	if rr := post(r, testLoginPath, "203.0.113.1", loginBody); rr.Code != http.StatusOK {
		t.Fatalf("successful login: got %d", rr.Code)
	}
	status = http.StatusUnauthorized
	for i := 0; i < 2; i++ {
		if rr := post(r, testLoginPath, "203.0.113.1", loginBody); rr.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d after reset: got %d, want 401 (counter was reset)", i+1, rr.Code)
		}
	}
	if rr := post(r, testLoginPath, "203.0.113.1", loginBody); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd failure after reset: got %d, want 429", rr.Code)
	}
}

func TestRateLimit_TokenPasswordGrantSharesIdentityLock(t *testing.T) {
	cfg := testConfig()
	cfg.LoginPerIP, cfg.TokenPerIP = 100, 100
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	r := newTestRouter(cfg, clock, http.StatusUnauthorized)

	post(r, testLoginPath, "203.0.113.1", loginBody)
	post(r, testLoginPath, "203.0.113.1", loginBody)

	passwordGrant := `{"grant_type":"password","email":"alice@example.com","password":"x"}`
	if rr := post(r, testTokenPath, "203.0.113.1", passwordGrant); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("password grant on /token must honour the /login identity lock: got %d", rr.Code)
	}
	refreshGrant := `{"grant_type":"refresh_token","refresh_token":"abc"}`
	if rr := post(r, testTokenPath, "203.0.113.1", refreshGrant); rr.Code != http.StatusUnauthorized {
		t.Fatalf("non-password grant must not be identity-locked: got %d", rr.Code)
	}
}

func TestRateLimit_BodyIsPassedThroughToHandler(t *testing.T) {
	limits := NewRateLimits(testConfig())
	var seen string
	h := limits.Login(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email string `json:"email"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		seen = req.Email
	}))
	post(h, testLoginPath, "203.0.113.1", loginBody)
	if seen != "alice@example.com" {
		t.Errorf("handler must still be able to read the body, got %q", seen)
	}
}

func TestRateLimit_MalformedBodyStillReachesHandler(t *testing.T) {
	limits := NewRateLimits(testConfig())
	h := limits.Login(statusHandler(http.StatusBadRequest))
	if rr := post(h, testLoginPath, "203.0.113.1", "{not json"); rr.Code != http.StatusBadRequest {
		t.Errorf("handler owns validation errors: got %d, want 400", rr.Code)
	}
}

func TestRateLimit_TrustedProxyUsesForwardedFor(t *testing.T) {
	cfg := testConfig()
	cfg.TrustedProxyCIDRs, _ = ratelimit.ParseCIDRs("10.0.0.0/8")
	cfg.RegisterPerIP = 1
	cfg.RegisterPerProject = 100
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	r := newTestRouter(cfg, clock, http.StatusOK)

	viaProxy := func(client string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, testRegisterPath, strings.NewReader(loginBody))
		req.RemoteAddr = "10.0.0.1:80"
		req.Header.Set("X-Forwarded-For", client)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		return rr
	}
	viaProxy("198.51.100.1")
	if rr := viaProxy("198.51.100.1"); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("same forwarded client: got %d, want 429", rr.Code)
	}
	if rr := viaProxy("198.51.100.2"); rr.Code != http.StatusCreated {
		t.Fatalf("different forwarded client: got %d, want 201", rr.Code)
	}
}

func TestRateLimit_UntrustedForwardedForCannotBypass(t *testing.T) {
	cfg := testConfig()
	cfg.RegisterPerIP = 1
	cfg.RegisterPerProject = 100
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	r := newTestRouter(cfg, clock, http.StatusOK)

	spoof := func(fake string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, testRegisterPath, strings.NewReader(loginBody))
		req.RemoteAddr = "203.0.113.1:80"
		req.Header.Set("X-Forwarded-For", fake)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		return rr
	}
	spoof("1.1.1.1")
	if rr := spoof("2.2.2.2"); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("rotating XFF from an untrusted peer must not bypass: got %d", rr.Code)
	}
}

func TestRateLimit_IncrementsMetricPerRoute(t *testing.T) {
	cfg := testConfig()
	cfg.RegisterPerIP = 1
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	r := newTestRouter(cfg, clock, http.StatusOK)
	counter := metrics.RateLimited.WithLabelValues("register")
	before := testutil.ToFloat64(counter)

	post(r, testRegisterPath, "203.0.113.1", loginBody)
	post(r, testRegisterPath, "203.0.113.1", loginBody)

	if got := testutil.ToFloat64(counter) - before; got != 1 {
		t.Errorf("auth_rate_limited_total{route=register} delta: got %v, want 1", got)
	}
}

func TestRateLimitConfigFrom(t *testing.T) {
	nets, _ := ratelimit.ParseCIDRs("10.0.0.0/8")
	got := RateLimitConfigFrom(config.RateLimit{
		WindowSeconds: 60, RegisterPerIP: 5, LoginPerIP: 10, TokenPerIP: 30,
		RegisterPerProject: 60, LoginFailures: 5, LoginFailureWindowSeconds: 900,
		TrustedProxyCIDRs: nets,
	})
	if got.Window != time.Minute || got.FailureWindow != 15*time.Minute {
		t.Errorf("windows: got %v / %v", got.Window, got.FailureWindow)
	}
	if got.RegisterPerIP != 5 || got.LoginPerIP != 10 || got.TokenPerIP != 30 || got.RegisterPerProject != 60 || got.LoginFailures != 5 {
		t.Errorf("limits: got %+v", got)
	}
	if len(got.TrustedProxyCIDRs) != 1 {
		t.Errorf("cidrs: got %v", got.TrustedProxyCIDRs)
	}
}
