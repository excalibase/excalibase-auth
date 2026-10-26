package handler

import "testing"

func TestOTPSenderKeyGroupsAnIPv6NetworkByItsPrefix(t *testing.T) {
	for raw, want := range map[string]string{
		"203.0.113.9":             "203.0.113.9",
		"2001:db8:1:2:aaaa::1":    "2001:db8:1:2::/64",
		"2001:db8:1:2:bbbb::ffff": "2001:db8:1:2::/64",
		"::ffff:203.0.113.9":      "203.0.113.9",
		"not-an-ip":               "not-an-ip",
		"":                        "",
	} {
		if got := otpSenderKey(raw); got != want {
			t.Errorf("otpSenderKey(%q) = %q, want %q", raw, got, want)
		}
	}
}
