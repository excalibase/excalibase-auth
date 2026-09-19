package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Guard against CI / local shell leakage of the env vars we care about.
	os.Unsetenv("ACCESS_TTL")
	os.Unsetenv("JWT_EXPIRATION")
	cfg := Load()
	if cfg.Port != "24000" {
		t.Errorf("port: got %s, want 24000", cfg.Port)
	}
	if cfg.ProvisioningURL != "http://localhost:24005/api" {
		t.Errorf("provisioningURL: got %s", cfg.ProvisioningURL)
	}
	if cfg.JWTExpiration != 86400 {
		t.Errorf("jwtExpiration: got %d", cfg.JWTExpiration)
	}
	if cfg.RefreshExpiration != 604800 {
		t.Errorf("refreshExpiration: got %d", cfg.RefreshExpiration)
	}
	if cfg.AccessTTL != 3600 {
		t.Errorf("accessTTL default: got %d, want 3600", cfg.AccessTTL)
	}
}

func TestAccessTTL_ExplicitEnvWins(t *testing.T) {
	t.Setenv("ACCESS_TTL", "1800")
	cfg := Load()
	if cfg.AccessTTL != 1800 {
		t.Errorf("ACCESS_TTL env: got %d, want 1800", cfg.AccessTTL)
	}
}

func TestAccessTTL_FallsBackToJWTExpiration(t *testing.T) {
	os.Unsetenv("ACCESS_TTL")
	t.Setenv("JWT_EXPIRATION", "7200")
	cfg := Load()
	if cfg.AccessTTL != 7200 {
		t.Errorf("fallback to JWT_EXPIRATION: got %d, want 7200", cfg.AccessTTL)
	}
}

func TestAccessTTL_InvalidFallsBackToDefault(t *testing.T) {
	os.Unsetenv("JWT_EXPIRATION")
	t.Setenv("ACCESS_TTL", "not-a-number")
	cfg := Load()
	if cfg.AccessTTL != 3600 {
		t.Errorf("invalid ACCESS_TTL should fall back to 3600: got %d", cfg.AccessTTL)
	}
}

func TestAccessTTL_ZeroOrNegativeGuarded(t *testing.T) {
	os.Unsetenv("JWT_EXPIRATION")
	t.Setenv("ACCESS_TTL", "0")
	cfg := Load()
	if cfg.AccessTTL != 3600 {
		t.Errorf("ACCESS_TTL=0 must be guarded: got %d, want 3600", cfg.AccessTTL)
	}

	t.Setenv("ACCESS_TTL", "-5")
	cfg = Load()
	if cfg.AccessTTL != 3600 {
		t.Errorf("ACCESS_TTL=-5 must be guarded: got %d, want 3600", cfg.AccessTTL)
	}
}

func TestLoadFromEnv(t *testing.T) {
	os.Setenv("PORT", "9000")
	os.Setenv("PROVISIONING_PAT", "excb_test123")
	defer os.Unsetenv("PORT")
	defer os.Unsetenv("PROVISIONING_PAT")

	cfg := Load()
	if cfg.Port != "9000" {
		t.Errorf("port: got %s", cfg.Port)
	}
	if cfg.ProvisioningPAT != "excb_test123" {
		t.Errorf("pat: got %s", cfg.ProvisioningPAT)
	}
}

func TestEnvIntValid(t *testing.T) {
	os.Setenv("JWT_EXPIRATION", "7200")
	defer os.Unsetenv("JWT_EXPIRATION")

	cfg := Load()
	if cfg.JWTExpiration != 7200 {
		t.Errorf("jwtExpiration: got %d", cfg.JWTExpiration)
	}
}

func TestEnvIntInvalid(t *testing.T) {
	os.Setenv("JWT_EXPIRATION", "not-a-number")
	defer os.Unsetenv("JWT_EXPIRATION")

	cfg := Load()
	if cfg.JWTExpiration != 86400 {
		t.Errorf("should fallback to default, got %d", cfg.JWTExpiration)
	}
}

func TestRateLimitDefaults(t *testing.T) {
	for _, key := range []string{
		"RATE_LIMIT_ENABLED", "RATE_LIMIT_WINDOW_SECONDS", "RATE_LIMIT_REGISTER_PER_IP",
		"RATE_LIMIT_LOGIN_PER_IP", "RATE_LIMIT_TOKEN_PER_IP", "RATE_LIMIT_REGISTER_PER_PROJECT",
		"RATE_LIMIT_LOGIN_FAILURES", "RATE_LIMIT_LOGIN_FAILURE_WINDOW_SECONDS", "TRUSTED_PROXY_CIDRS",
	} {
		os.Unsetenv(key)
	}
	cfg := Load()
	rl := cfg.RateLimit
	if !rl.Enabled {
		t.Error("rate limiting must be enabled by default")
	}
	if rl.WindowSeconds != 60 || rl.RegisterPerIP != 5 || rl.LoginPerIP != 10 || rl.TokenPerIP != 30 {
		t.Errorf("per-ip defaults: got %+v", rl)
	}
	if rl.RegisterPerProject != 60 {
		t.Errorf("register per project: got %d, want 60", rl.RegisterPerProject)
	}
	if rl.LoginFailures != 5 || rl.LoginFailureWindowSeconds != 900 {
		t.Errorf("login failure defaults: got %d/%d, want 5/900", rl.LoginFailures, rl.LoginFailureWindowSeconds)
	}
	if len(rl.TrustedProxyCIDRs) != 0 {
		t.Errorf("no proxies trusted by default, got %v", rl.TrustedProxyCIDRs)
	}
}

func TestRateLimitFromEnv(t *testing.T) {
	t.Setenv("RATE_LIMIT_ENABLED", "false")
	t.Setenv("RATE_LIMIT_WINDOW_SECONDS", "120")
	t.Setenv("RATE_LIMIT_REGISTER_PER_IP", "7")
	t.Setenv("RATE_LIMIT_LOGIN_PER_IP", "8")
	t.Setenv("RATE_LIMIT_TOKEN_PER_IP", "9")
	t.Setenv("RATE_LIMIT_REGISTER_PER_PROJECT", "70")
	t.Setenv("RATE_LIMIT_LOGIN_FAILURES", "3")
	t.Setenv("RATE_LIMIT_LOGIN_FAILURE_WINDOW_SECONDS", "600")
	t.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 192.168.0.0/16")

	rl := Load().RateLimit
	if rl.Enabled {
		t.Error("RATE_LIMIT_ENABLED=false must disable")
	}
	if rl.WindowSeconds != 120 || rl.RegisterPerIP != 7 || rl.LoginPerIP != 8 || rl.TokenPerIP != 9 {
		t.Errorf("per-ip env: got %+v", rl)
	}
	if rl.RegisterPerProject != 70 || rl.LoginFailures != 3 || rl.LoginFailureWindowSeconds != 600 {
		t.Errorf("project/failure env: got %+v", rl)
	}
	if len(rl.TrustedProxyCIDRs) != 2 {
		t.Errorf("trusted cidrs: got %v, want 2 entries", rl.TrustedProxyCIDRs)
	}
}

func TestEnvBool(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{raw: "", want: true},
		{raw: "true", want: true},
		{raw: "1", want: true},
		{raw: "false", want: false},
		{raw: "0", want: false},
		{raw: "garbage", want: true},
	}
	for _, tt := range tests {
		t.Run("value="+tt.raw, func(t *testing.T) {
			t.Setenv("RATE_LIMIT_ENABLED", tt.raw)
			if got := envBool("RATE_LIMIT_ENABLED", true); got != tt.want {
				t.Errorf("envBool(%q): got %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

// TestLoadExposesProvisioningPATFile checks that Load only surfaces the raw
// PROVISIONING_PAT_FILE path; reading its contents (and re-reading on
// rotation) is internal/token's job, not config's, so ProvisioningPAT stays
// whatever PROVISIONING_PAT itself was (empty here).
func TestLoadExposesProvisioningPATFile(t *testing.T) {
	os.Unsetenv("PROVISIONING_PAT")
	dir := t.TempDir()
	path := filepath.Join(dir, "pat")
	if err := os.WriteFile(path, []byte(" excb_from_file \n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	t.Setenv("PROVISIONING_PAT_FILE", path)

	cfg := Load()

	if cfg.ProvisioningPATFile != path {
		t.Errorf("ProvisioningPATFile: got %q, want %q", cfg.ProvisioningPATFile, path)
	}
	if cfg.ProvisioningPAT != "" {
		t.Errorf("ProvisioningPAT: got %q, want empty — config no longer reads the file itself", cfg.ProvisioningPAT)
	}
}
