package config

import "testing"

func TestRequestMetrics_OffUnlessExactlyTrue(t *testing.T) {
	for _, value := range []string{"", "false", "TRUE", "1", "yes"} {
		t.Setenv("REQUEST_METRICS_ENABLED", value)
		if Load().RequestMetrics.Enabled {
			t.Errorf("REQUEST_METRICS_ENABLED=%q turned the request charts on", value)
		}
	}
}

func TestRequestMetrics_DefaultsToItsOwnPortAndCap(t *testing.T) {
	t.Setenv("REQUEST_METRICS_ENABLED", "true")
	got := Load().RequestMetrics
	if !got.Enabled || got.Port != "9465" || got.MaxProjects != 1000 || got.Address != "" {
		t.Errorf("defaults: %+v", got)
	}
}

func TestRequestMetrics_PortAndCapFromTheEnvironment(t *testing.T) {
	t.Setenv("REQUEST_METRICS_ENABLED", "true")
	t.Setenv("REQUEST_METRICS_PORT", "9999")
	t.Setenv("REQUEST_METRICS_MAX_PROJECTS", "50")
	got := Load().RequestMetrics
	if got.Port != "9999" || got.MaxProjects != 50 {
		t.Errorf("from env: %+v", got)
	}
}

func TestRequestMetrics_ANonPositiveCapFallsBackToTheDefault(t *testing.T) {
	t.Setenv("REQUEST_METRICS_MAX_PROJECTS", "0")
	if got := Load().RequestMetrics.MaxProjects; got != 1000 {
		t.Errorf("cap: got %d", got)
	}
}

func TestRequestMetrics_AddressFromTheEnvironment(t *testing.T) {
	t.Setenv("REQUEST_METRICS_ADDRESS", " auth-metrics ")
	if got := Load().RequestMetrics.Address; got != "auth-metrics" {
		t.Errorf("address: %q", got)
	}
}
