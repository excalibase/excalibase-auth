package config

import "testing"

func TestTenantDBSSLModeDefaultsToVerifyFull(t *testing.T) {
	got, err := parseTenantDBSSLMode("")
	if err != nil || got != "verify-full" {
		t.Fatalf("got %q, %v; want verify-full", got, err)
	}
}

// Platform roles authenticate by client certificate, which only means
// something against a verified server, so every TLS spelling is verify-full.
func TestTenantDBSSLModeUpgradesEveryTLSModeToVerifyFull(t *testing.T) {
	for _, mode := range []string{"require", "verify-ca", "verify-full"} {
		if got, err := parseTenantDBSSLMode(mode); err != nil || got != "verify-full" {
			t.Errorf("%s: got %q, %v; want verify-full", mode, got, err)
		}
	}
}

func TestTenantDBSSLModeKeepsDisableForTheDockerAIO(t *testing.T) {
	if got, err := parseTenantDBSSLMode("disable"); err != nil || got != "disable" {
		t.Fatalf("got %q, %v; want disable", got, err)
	}
}

func TestTenantDBSSLModeRefusesSilentDowngradeAndUnknownModes(t *testing.T) {
	for _, mode := range []string{"prefer", "allow", "required", "on"} {
		if _, err := parseTenantDBSSLMode(mode); err == nil {
			t.Errorf("%s must be refused", mode)
		}
	}
}
