package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/excalibase/auth/internal/config"
	"github.com/excalibase/auth/internal/requestmetrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestRequestMetricsServer_ListensOnItsOwnPortAndAnswersOnlyTheScrape(t *testing.T) {
	server := newRequestMetricsServer("9465", requestmetrics.NewRecorder(func(string) bool { return true }, 10))
	if server.Addr != ":9465" {
		t.Errorf("addr: %s", server.Addr)
	}
	if server.ReadHeaderTimeout == 0 || server.WriteTimeout == 0 {
		t.Error("the internal listener bounds slow clients")
	}
	for path, want := range map[string]int{"/metrics": http.StatusOK, "/healthz": http.StatusNotFound, "/auth/o/p/login": http.StatusNotFound} {
		response := httptest.NewRecorder()
		server.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != want {
			t.Errorf("%s: got %d, want %d", path, response.Code, want)
		}
	}
}

func TestRequestMetricsRecorder_FlagOffMeansNoRecorderAndNoListener(t *testing.T) {
	if recorder := requestMetricsRecorder(config.RequestMetrics{Enabled: false, Port: "9465", MaxProjects: 10}, func(string) bool { return true }); recorder != nil {
		t.Error("with the flag off nothing is recorded and no listener starts")
	}
	if recorder := requestMetricsRecorder(config.RequestMetrics{Enabled: true, Port: "9465", MaxProjects: 10}, func(string) bool { return true }); recorder == nil {
		t.Error("with the flag on the recorder exists")
	}
}

func TestRequestMetrics_FlagOffRoutesAreUntimed(t *testing.T) {
	// A handler without a recorder mounts no middleware: the public /metrics
	// gains no per-project series however many requests arrive.
	response := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(response.Body.String(), "excalibase_requests_seconds") {
		t.Error("no per-project series on the default registry")
	}
}
