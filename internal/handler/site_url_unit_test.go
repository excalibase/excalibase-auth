package handler

import "testing"

func TestNormalizeSiteURL(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"https origin", "https://app.example.com", "https://app.example.com"},
		{"trailing slash trimmed", "https://app.example.com/", "https://app.example.com"},
		{"path kept", "https://example.com/app/", "https://example.com/app"},
		{"port kept", "https://example.com:8443", "https://example.com:8443"},
		{"localhost http", "http://localhost:3000", "http://localhost:3000"},
		{"loopback http", "http://127.0.0.1:5173", "http://127.0.0.1:5173"},
		{"surrounding space", "  https://a.example.com ", "https://a.example.com"},
		{"empty", "", ""},
		{"relative path", "/app", ""},
		{"no scheme", "app.example.com", ""},
		{"http on a real host", "http://app.example.com", ""},
		{"other scheme", "javascript:alert(1)", ""},
		{"ftp", "ftp://example.com", ""},
		{"no host", "https://", ""},
		{"userinfo", "https://user:pw@example.com", ""},
		{"query", "https://example.com/?a=b", ""},
		{"fragment", "https://example.com/#x", ""},
		{"localhost lookalike", "http://localhost.evil.com", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := normalizeSiteURL(c.in); got != c.want {
				t.Errorf("normalizeSiteURL(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestLinksAreAbsolute(t *testing.T) {
	if got := resetLink("https://a.example.com", "t k"); got != "https://a.example.com/reset-password?token=t+k" {
		t.Errorf("resetLink: %q", got)
	}
	if got := verificationLink("https://a.example.com", "tok"); got != "https://a.example.com/verify?token=tok" {
		t.Errorf("verificationLink: %q", got)
	}
}
