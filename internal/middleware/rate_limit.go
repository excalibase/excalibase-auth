package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/excalibase/auth/internal/config"
	"github.com/excalibase/auth/internal/metrics"
	"github.com/excalibase/auth/internal/ratelimit"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// Logical route labels for the auth_rate_limited_total metric. They are a
// small fixed set on purpose (see the metrics package on cardinality).
const (
	routeRegister = "register"
	routeLogin    = "login"
	routeToken    = "token"

	grantPassword = "password"

	// maxIdentityBodyBytes bounds how much of the request body the identity
	// guard buffers. Login/register payloads are a few hundred bytes; a body
	// beyond this is truncated for the downstream handler, which then fails
	// JSON decoding with the usual 400.
	maxIdentityBodyBytes = 1 << 20
)

// RateLimitConfig is the middleware's view of the limits. Per-IP and
// per-project limiters share Window; the login failure lock uses
// FailureWindow.
type RateLimitConfig struct {
	Window             time.Duration
	RegisterPerIP      int
	LoginPerIP         int
	TokenPerIP         int
	RegisterPerProject int
	LoginFailures      int
	FailureWindow      time.Duration
	TrustedProxyCIDRs  []*net.IPNet
}

// RateLimitConfigFrom adapts the env-derived config into middleware terms.
func RateLimitConfigFrom(cfg config.RateLimit) RateLimitConfig {
	return RateLimitConfig{
		Window:             time.Duration(cfg.WindowSeconds) * time.Second,
		RegisterPerIP:      cfg.RegisterPerIP,
		LoginPerIP:         cfg.LoginPerIP,
		TokenPerIP:         cfg.TokenPerIP,
		RegisterPerProject: cfg.RegisterPerProject,
		LoginFailures:      cfg.LoginFailures,
		FailureWindow:      time.Duration(cfg.LoginFailureWindowSeconds) * time.Second,
		TrustedProxyCIDRs:  cfg.TrustedProxyCIDRs,
	}
}

// RateLimits owns one limiter per policy and exposes a chi middleware per
// credential route. Register/Login/Token each apply the per-IP budget for
// that route; Register additionally caps registrations per project, and
// Login/Token (password grant) share the per-identity failure lock so the
// legacy and OAuth2-shaped entry points cannot be played against each other.
type RateLimits struct {
	registerIP      *ratelimit.Limiter
	loginIP         *ratelimit.Limiter
	tokenIP         *ratelimit.Limiter
	registerProject *ratelimit.Limiter
	loginFailures   *ratelimit.Limiter
	trusted         []*net.IPNet
}

// NewRateLimits builds the limiters. Options (e.g. ratelimit.WithClock) are
// applied to every limiter.
func NewRateLimits(cfg RateLimitConfig, opts ...ratelimit.Option) *RateLimits {
	return &RateLimits{
		registerIP:      ratelimit.New(cfg.RegisterPerIP, cfg.Window, opts...),
		loginIP:         ratelimit.New(cfg.LoginPerIP, cfg.Window, opts...),
		tokenIP:         ratelimit.New(cfg.TokenPerIP, cfg.Window, opts...),
		registerProject: ratelimit.New(cfg.RegisterPerProject, cfg.Window, opts...),
		loginFailures:   ratelimit.New(cfg.LoginFailures, cfg.FailureWindow, opts...),
		trusted:         cfg.TrustedProxyCIDRs,
	}
}

// Register throttles POST /register per client IP and per project.
func (rl *RateLimits) Register(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if decision := rl.registerIP.Allow(rl.clientIP(r)); decision.Blocked() {
			reject(w, routeRegister, decision)
			return
		}
		if project := chi.URLParam(r, "projectId"); project != "" {
			if decision := rl.registerProject.Allow(project); decision.Blocked() {
				reject(w, routeRegister, decision)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Login throttles POST /login per client IP and locks an identity after
// repeated failures.
func (rl *RateLimits) Login(next http.Handler) http.Handler {
	guarded := rl.identityGuard(next, routeLogin, func(c credentials) string { return c.Email })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if decision := rl.loginIP.Allow(rl.clientIP(r)); decision.Blocked() {
			reject(w, routeLogin, decision)
			return
		}
		guarded.ServeHTTP(w, r)
	})
}

// Token throttles POST /token per client IP; the password grant additionally
// shares the /login identity lock.
func (rl *RateLimits) Token(next http.Handler) http.Handler {
	guarded := rl.identityGuard(next, routeToken, func(c credentials) string {
		if c.GrantType != grantPassword {
			return ""
		}
		return c.Email
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if decision := rl.tokenIP.Allow(rl.clientIP(r)); decision.Blocked() {
			reject(w, routeToken, decision)
			return
		}
		guarded.ServeHTTP(w, r)
	})
}

func (rl *RateLimits) clientIP(r *http.Request) string {
	return ratelimit.ClientIP(r, rl.trusted)
}

// credentials is the subset of the login/token body needed to derive the
// identity key. The raw value is hashed immediately and never logged.
type credentials struct {
	Email     string `json:"email"`
	GrantType string `json:"grant_type"`
}

// identityGuard implements "check before, charge after": a locked identity
// is rejected without touching the database; otherwise the handler runs and
// its status decides whether to record a failure (401/403) or clear the
// counter (2xx). Other statuses (400, 5xx) leave the counter untouched.
func (rl *RateLimits) identityGuard(next http.Handler, route string, identityOf func(credentials) string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := ratelimit.IdentityKey(identityOf(peekCredentials(r)))
		if key == "" {
			next.ServeHTTP(w, r)
			return
		}
		if decision := rl.loginFailures.Exhausted(key); decision.Blocked() {
			reject(w, route, decision)
			return
		}
		ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		switch status := ww.Status(); {
		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			rl.loginFailures.Allow(key)
		case status >= 200 && status < 300:
			rl.loginFailures.Reset(key)
		}
	})
}

// peekCredentials reads the body to extract the identity and puts an
// equivalent body back so the handler can decode it again. A malformed body
// yields zero credentials; validation stays the handler's responsibility.
func peekCredentials(r *http.Request) credentials {
	var creds credentials
	if r.Body == nil {
		return creds
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxIdentityBodyBytes))
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return credentials{}
	}
	_ = json.Unmarshal(body, &creds)
	return creds
}

// reject writes the 429 contract: Retry-After header, JSON body with the
// same value, and one metric increment for the route.
func reject(w http.ResponseWriter, route string, decision ratelimit.Decision) {
	seconds := int(math.Ceil(decision.RetryAfter.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	metrics.RateLimited.WithLabelValues(route).Inc()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":      "rate_limited",
		"retryAfter": seconds,
	})
}
