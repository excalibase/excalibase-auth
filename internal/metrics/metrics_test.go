package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestHandler_Returns200AndExposesMetricNames(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()

	Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, name := range []string{
		"auth_signups_total",
		"auth_logins_total",
		"auth_login_failures_total",
	} {
		if !strings.Contains(body, name) {
			t.Errorf("/metrics output missing %q", name)
		}
	}
}

func TestMiddleware_IncrementsHTTPCounter(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Middleware)
	r.Get("/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	before := testutil.ToFloat64(httpRequests.WithLabelValues("/ping", http.MethodGet, "200"))

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)

	after := testutil.ToFloat64(httpRequests.WithLabelValues("/ping", http.MethodGet, "200"))
	if after-before != 1 {
		t.Errorf("http counter delta: got %v, want 1", after-before)
	}
}
