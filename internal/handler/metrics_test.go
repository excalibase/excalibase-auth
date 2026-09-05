package handler

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/excalibase/auth/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// A login that cannot reach the project DB is still a failed login and must be
// counted. Uses the unreachable-vault router so no container is required.
func TestMetrics_LoginFailure_IncrementsCounter(t *testing.T) {
	r := setupUnitRouter(t)
	before := testutil.ToFloat64(metrics.LoginFailures)

	body := `{"email":"a@b.com","password":"pass"}`
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(httptest.NewRecorder(), req)

	if after := testutil.ToFloat64(metrics.LoginFailures); after-before != 1 {
		t.Errorf("login_failures delta: got %v, want 1", after-before)
	}
}

func TestIntegration_Metrics_RegisterAndLoginSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	signupsBefore := testutil.ToFloat64(metrics.Signups)
	loginsBefore := testutil.ToFloat64(metrics.Logins)

	resp := postJSON(srv, "/auth/test-org/test-project/register", map[string]string{
		"email": "metrics@test.com", "password": "password123", "fullName": "Metrics",
	})
	if resp.StatusCode != 201 {
		t.Fatalf("register: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	if got := testutil.ToFloat64(metrics.Signups) - signupsBefore; got != 1 {
		t.Errorf("signups delta: got %v, want 1", got)
	}

	resp = postJSON(srv, "/auth/test-org/test-project/login", map[string]string{
		"email": "metrics@test.com", "password": "password123",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("login: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	if got := testutil.ToFloat64(metrics.Logins) - loginsBefore; got != 1 {
		t.Errorf("logins delta: got %v, want 1", got)
	}
}
