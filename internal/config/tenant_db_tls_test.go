package config

import "testing"

func TestTenantDBSSLModeDefaultsToRequire(t *testing.T) {
	got, err := parseTenantDBSSLMode("")
	if err != nil || got != "require" {
		t.Fatalf("got %q, %v; want require", got, err)
	}
}

func TestTenantDBSSLModeAcceptsExplicitModes(t *testing.T) {
	for _, mode := range []string{"disable", "require", "verify-ca", "verify-full"} {
		if got, err := parseTenantDBSSLMode(mode); err != nil || got != mode {
			t.Errorf("%s: got %q, %v", mode, got, err)
		}
	}
}

func TestTenantDBSSLModeRefusesSilentDowngradeAndUnknownModes(t *testing.T) {
	for _, mode := range []string{"prefer", "allow", "required", "on"} {
		if _, err := parseTenantDBSSLMode(mode); err == nil {
			t.Errorf("%s must be refused", mode)
		}
	}
}
