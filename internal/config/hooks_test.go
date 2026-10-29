package config

import (
	"net/netip"
	"testing"
)

func TestParseHookDenyCIDRs(t *testing.T) {
	got, err := parseHookDenyCIDRs(" 203.0.113.0/24, 2001:db8::/32 ,198.51.100.7/32")
	want := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("198.51.100.7/32")}
	if err != nil || len(got) != len(want) {
		t.Fatalf("got %v, %v", got, err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if got, err := parseHookDenyCIDRs(""); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v, %v", got, err)
	}
	for _, bad := range []string{"not-a-cidr", "203.0.113.0", "300.0.0.0/8"} {
		if _, err := parseHookDenyCIDRs(bad); err == nil {
			t.Errorf("parseHookDenyCIDRs(%q) accepted", bad)
		}
	}
}

func TestLoadReadsTheHookSettings(t *testing.T) {
	t.Setenv("AUTH_HOOKS_DENY_CIDRS", "203.0.113.0/24")
	t.Setenv("AUTH_HOOKS_CA_FILE", "/etc/excalibase/hooks-ca/ca.crt")
	cfg := Load()
	if len(cfg.Hooks.DenyCIDRs) != 1 || cfg.Hooks.CAFile != "/etc/excalibase/hooks-ca/ca.crt" {
		t.Fatalf("hooks = %+v", cfg.Hooks)
	}
}
