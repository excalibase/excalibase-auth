package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
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
