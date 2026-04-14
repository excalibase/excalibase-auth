package config

import (
	"os"
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
