package config

import (
	"testing"
	"time"
)

func TestProjectCORSTTLDefaultsToThirtySeconds(t *testing.T) {
	t.Setenv("PROJECT_CORS_TTL_SECONDS", "")
	if got := projectCORSTTL(); got != 30*time.Second {
		t.Errorf("ttl = %v, want 30s", got)
	}
}

func TestProjectCORSTTLReadsTheEnv(t *testing.T) {
	t.Setenv("PROJECT_CORS_TTL_SECONDS", "10")
	if got := projectCORSTTL(); got != 10*time.Second {
		t.Errorf("ttl = %v, want 10s", got)
	}
}

// A zero or negative TTL would re-fetch on every request; it falls back.
func TestProjectCORSTTLRejectsNonPositiveValues(t *testing.T) {
	for _, raw := range []string{"0", "-5", "abc"} {
		t.Setenv("PROJECT_CORS_TTL_SECONDS", raw)
		if got := projectCORSTTL(); got != 30*time.Second {
			t.Errorf("%q: ttl = %v, want 30s", raw, got)
		}
	}
}
