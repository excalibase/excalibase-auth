// Package metrics provides lean Prometheus instrumentation for the auth
// service: a /metrics exposition handler, an HTTP request counter fed by a chi
// middleware, and a few auth-business counters incremented by the handlers.
//
// Cardinality is kept bounded on purpose. The HTTP counter is labeled by the
// matched chi route pattern (a small fixed set), not the raw path, and the
// business counters carry no per-tenant labels — orgSlug/projectId are
// effectively unbounded and would blow up the series count.
package metrics

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_http_requests_total",
		Help: "Total HTTP requests handled, labeled by route pattern, method and status.",
	}, []string{"route", "method", "status"})

	// Signups counts successful user registrations.
	Signups = promauto.NewCounter(prometheus.CounterOpts{
		Name: "auth_signups_total",
		Help: "Total successful user registrations.",
	})

	// Logins counts successful password logins.
	Logins = promauto.NewCounter(prometheus.CounterOpts{
		Name: "auth_logins_total",
		Help: "Total successful logins.",
	})

	// LoginFailures counts failed login attempts (bad credentials, disabled
	// account, or an unreachable project database).
	LoginFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "auth_login_failures_total",
		Help: "Total failed login attempts.",
	})

	// RateLimited counts requests rejected with 429 by the credential-endpoint
	// limiter, labeled by the logical route (register, login, token).
	RateLimited = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_rate_limited_total",
		Help: "Total requests rejected by rate limiting, labeled by route.",
	}, []string{"route"})
)

// Handler serves the Prometheus exposition format for scraping.
func Handler() http.Handler {
	return promhttp.Handler()
}

// Middleware records one auth_http_requests_total observation per request. The
// route label is the matched chi pattern, resolved after the downstream
// handler runs so the router has populated the route context.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unmatched"
		}
		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}
		httpRequests.WithLabelValues(route, r.Method, strconv.Itoa(status)).Inc()
	})
}
