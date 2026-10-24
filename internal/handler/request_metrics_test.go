package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/excalibase/auth/internal/requestmetrics"
)

func scrapeRequests(t *testing.T, recorder *requestmetrics.Recorder) string {
	t.Helper()
	response := httptest.NewRecorder()
	recorder.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return response.Body.String()
}

// The vault is unreachable here, so no project is served and none is recorded.
func TestRequestMetrics_AProjectTheVaultDoesNotServeIsNotRecorded(t *testing.T) {
	var recorder *requestmetrics.Recorder
	router := setupUnitRouterWith(t, func(h *AuthHandler) *AuthHandler {
		recorder = requestmetrics.NewRecorder(h.poolMgr.Serves, 10)
		return h.WithRequestMetrics(recorder)
	})
	request := httptest.NewRequest(http.MethodPost, "/auth/test-org/not-a-project/login", strings.NewReader(`{"email":"a@b.com","password":"pass"}`))
	router.ServeHTTP(httptest.NewRecorder(), request)

	if body := scrapeRequests(t, recorder); strings.Contains(body, "not-a-project") {
		t.Errorf("unknown project recorded:\n%s", body)
	}
}

func TestIntegration_RequestMetrics_CountsAProjectsCallsByOutcome(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	var recorder *requestmetrics.Recorder
	fx, cleanup := setupIntegrationFixture(t, func(h *AuthHandler) *AuthHandler {
		recorder = requestmetrics.NewRecorder(h.poolMgr.Serves, 10)
		return h.WithRequestMetrics(recorder)
	})
	defer cleanup()

	registered := postJSON(fx.srv, "/auth/test-org/test-project/register", map[string]string{
		"email": "charts@test.com", "password": "password123", "fullName": "Charts",
	})
	registered.Body.Close()
	refused := postJSON(fx.srv, "/auth/test-org/test-project/login", map[string]string{
		"email": "charts@test.com", "password": "wrong-password",
	})
	refused.Body.Close()
	if registered.StatusCode >= 300 || refused.StatusCode != http.StatusUnauthorized {
		t.Fatalf("register %d, bad login %d", registered.StatusCode, refused.StatusCode)
	}

	body := scrapeRequests(t, recorder)
	for _, line := range []string{
		`excalibase_requests_seconds_count{family="auth",outcome="ok",project="test-project"} 1`,
		`excalibase_requests_seconds_count{family="auth",outcome="client_error",project="test-project"} 1`,
	} {
		if !strings.Contains(body, line) {
			t.Errorf("missing %q in\n%s", line, body)
		}
	}
}
