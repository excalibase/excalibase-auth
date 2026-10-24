package requestmetrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func knownProjects(ids ...string) func(string) bool {
	known := map[string]bool{}
	for _, id := range ids {
		known[id] = true
	}
	return func(projectID string) bool { return known[projectID] }
}

// projectRouter mounts the middleware where auth does: inside the project route.
func projectRouter(recorder *Recorder, status int) http.Handler {
	router := chi.NewRouter()
	router.Route("/auth/{orgSlug}/{projectId}", func(r chi.Router) {
		r.Use(recorder.Middleware)
		r.Post("/login", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
	})
	return router
}

func call(t *testing.T, handler http.Handler, path string) {
	t.Helper()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, path, nil))
}

func scrape(t *testing.T, recorder *Recorder) string {
	t.Helper()
	response := httptest.NewRecorder()
	recorder.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("scrape: %d", response.Code)
	}
	return response.Body.String()
}

func TestMiddleware_CountsAKnownProjectsRequestsByOutcome(t *testing.T) {
	recorder := NewRecorder(knownProjects("p1"), 10)
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusUnauthorized, http.StatusServiceUnavailable} {
		call(t, projectRouter(recorder, status), "/auth/acme/p1/login")
	}

	body := scrape(t, recorder)
	for _, line := range []string{
		`excalibase_requests_seconds_count{family="auth",outcome="ok",project="p1"} 2`,
		`excalibase_requests_seconds_count{family="auth",outcome="client_error",project="p1"} 1`,
		`excalibase_requests_seconds_count{family="auth",outcome="server_error",project="p1"} 1`,
	} {
		if !strings.Contains(body, line) {
			t.Errorf("missing %q in\n%s", line, body)
		}
	}
}

func TestMiddleware_AProjectAuthDoesNotServeIsNeverRecorded(t *testing.T) {
	recorder := NewRecorder(knownProjects("p1"), 10)
	call(t, projectRouter(recorder, http.StatusNotFound), "/auth/acme/..%2Fsecret-token/login")
	call(t, projectRouter(recorder, http.StatusInternalServerError), "/auth/acme/random/login")

	body := scrape(t, recorder)
	if strings.Contains(body, `project="random"`) || strings.Contains(body, "secret-token") {
		t.Errorf("an unknown project made a series:\n%s", body)
	}
}

func TestMiddleware_ProjectsPastTheCapAreDroppedNotRecorded(t *testing.T) {
	recorder := NewRecorder(knownProjects("p1", "p2", "p3"), 2)
	for _, project := range []string{"p1", "p2", "p3", "p1"} {
		call(t, projectRouter(recorder, http.StatusOK), "/auth/acme/"+project+"/login")
	}

	body := scrape(t, recorder)
	if !strings.Contains(body, `excalibase_requests_seconds_count{family="auth",outcome="ok",project="p1"} 2`) {
		t.Errorf("an admitted project keeps counting:\n%s", body)
	}
	if strings.Contains(body, `project="p3"`) {
		t.Errorf("the project past the cap got a series:\n%s", body)
	}
	if !strings.Contains(body, "excalibase_request_metrics_dropped_total 1") {
		t.Errorf("the dropped request is counted:\n%s", body)
	}
}

func TestScrape_LatencyBucketsAreTheFixedSetProvisioningMerges(t *testing.T) {
	recorder := NewRecorder(knownProjects("p1"), 10)
	call(t, projectRouter(recorder, http.StatusOK), "/auth/acme/p1/login")

	body := scrape(t, recorder)
	for _, le := range []string{"0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2.5", "5", "10", "+Inf"} {
		line := `excalibase_requests_seconds_bucket{family="auth",outcome="ok",project="p1",le="` + le + `"}`
		if !strings.Contains(body, line) {
			t.Errorf("missing bucket le=%s", le)
		}
	}
}

func TestScrape_NamesThisProcessSoACounterResetIsSeen(t *testing.T) {
	first := scrape(t, NewRecorder(knownProjects(), 10))
	second := scrape(t, NewRecorder(knownProjects(), 10))
	info := regexp.MustCompile(`excalibase_request_metrics_info\{instance="([0-9a-f-]{36})"\} 1`)
	a, b := info.FindStringSubmatch(first), info.FindStringSubmatch(second)
	if a == nil || b == nil {
		t.Fatalf("no info line:\n%s", first)
	}
	if a[1] == b[1] {
		t.Error("each process has its own instance id")
	}
	started := regexp.MustCompile(`excalibase_request_metrics_start_time_seconds\{instance="` + a[1] + `"\} [1-9]`)
	if !started.MatchString(first) {
		t.Errorf("the start time is its own series, as the engine exposes it:\n%s", first)
	}
}

func TestScrape_StaysOffTheDefaultRegistry(t *testing.T) {
	recorder := NewRecorder(knownProjects("p1"), 10)
	call(t, projectRouter(recorder, http.StatusOK), "/auth/acme/p1/login")

	response := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(response.Body.String(), "excalibase_requests_seconds") {
		t.Error("per-project series must not reach the public /metrics")
	}
}

func TestServer_AnswersOnlyTheScrape(t *testing.T) {
	recorder := NewRecorder(knownProjects(), 10)
	server := httptest.NewServer(recorder.ServerMux())
	defer server.Close()

	cases := []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/metrics", http.StatusOK},
		{http.MethodGet, "/healthz", http.StatusNotFound},
		{http.MethodGet, "/auth/acme/p1/login", http.StatusNotFound},
		{http.MethodPost, "/metrics", http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		request, _ := http.NewRequest(tc.method, server.URL+tc.path, nil)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != tc.want {
			t.Errorf("%s %s: got %d, want %d", tc.method, tc.path, response.StatusCode, tc.want)
		}
	}
}
