package publicaddr

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateHostSyntax_Rejected(t *testing.T) {
	rejected := []struct{ name, host string }{
		{"empty", ""},
		{"blank", "   "},
		{"multi-host comma", "a.example.com,b.example.com"},
		{"hostaddr injected via space", "a.example.com hostaddr=169.254.169.254"},
		{"host injected via space", "a.example.com host=127.0.0.1"},
		{"tab separated", "a.example.com\thost=127.0.0.1"},
		{"equals sign", "host=127.0.0.1"},
		{"embedded port", "a.example.com:5432"},
		{"url form", "postgres://a.example.com/db"},
		{"path", "a.example.com/db"},
		{"query", "a.example.com?host=127.0.0.1"},
		{"userinfo", "user@a.example.com"},
		{"quote", "a.example.com'"},
		{"backslash", "a.example.com\\"},
		{"ipv6 zone id", "fe80::1%eth0"},
		{"bracketed ipv6 zone id", "[fe80::1%25eth0]"},
		{"control char", "a.example.com\x00"},
		{"unix socket dir", "/var/run/postgresql"},
		{"leading dot", ".example.com"},
		{"double dot", "a..example.com"},
		{"leading hyphen label", "-a.example.com"},
		{"too long label", strings.Repeat("a", 64) + ".example.com"},
		{"too long name", strings.Repeat("a.", 130) + "com"},
		{"underscore label", "my_db.example.com"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHostSyntax(tc.host)
			if !errors.Is(err, ErrInvalidHost) {
				t.Fatalf("ValidateHostSyntax(%q) = %v, want ErrInvalidHost", tc.host, err)
			}
		})
	}
}

func TestValidateHostSyntax_Accepted(t *testing.T) {
	accepted := []string{
		"db.example.com",
		"DB.Example.COM",
		"my-host.acme.io",
		"db.example.com.",
		"8.8.8.8",
		"2001:4860:4860::8888",
		"[2001:4860:4860::8888]",
		"a1.b2.c3",
		"xn--bcher-kva.example",
	}
	for _, host := range accepted {
		if err := ValidateHostSyntax(host); err != nil {
			t.Errorf("ValidateHostSyntax(%q) = %v, want nil", host, err)
		}
	}
}
