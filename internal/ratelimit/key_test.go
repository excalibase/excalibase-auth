package ratelimit

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseCIDRs(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantLen int
		wantErr bool
	}{
		{name: "empty means no trusted proxies", raw: "", wantLen: 0},
		{name: "single cidr", raw: "10.0.0.0/8", wantLen: 1},
		{name: "multiple with whitespace", raw: " 10.0.0.0/8 , 192.168.1.0/24,fd00::/8 ", wantLen: 3},
		{name: "bare ip becomes host cidr", raw: "10.1.2.3", wantLen: 1},
		{name: "garbage is rejected", raw: "not-a-cidr", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nets, err := ParseCIDRs(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err: got %v, wantErr %v", err, tt.wantErr)
			}
			if len(nets) != tt.wantLen {
				t.Errorf("len: got %d, want %d", len(nets), tt.wantLen)
			}
		})
	}
}

func TestClientIP(t *testing.T) {
	trusted, err := ParseCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		trusted    []*net.IPNet
		want       string
	}{
		{
			name:       "no proxies configured: XFF is ignored",
			remoteAddr: "203.0.113.7:4321",
			xff:        "198.51.100.9",
			trusted:    nil,
			want:       "203.0.113.7",
		},
		{
			name:       "untrusted peer sending XFF is ignored (bypass attempt)",
			remoteAddr: "203.0.113.7:4321",
			xff:        "198.51.100.9",
			trusted:    trusted,
			want:       "203.0.113.7",
		},
		{
			name:       "trusted proxy: single XFF hop",
			remoteAddr: "10.1.1.1:80",
			xff:        "198.51.100.9",
			trusted:    trusted,
			want:       "198.51.100.9",
		},
		{
			name:       "trusted proxy: rightmost untrusted hop wins, not client-forged leftmost",
			remoteAddr: "10.1.1.1:80",
			xff:        "1.2.3.4, 198.51.100.9, 10.2.2.2",
			trusted:    trusted,
			want:       "198.51.100.9",
		},
		{
			name:       "trusted proxy: all hops trusted falls back to leftmost",
			remoteAddr: "10.1.1.1:80",
			xff:        "10.3.3.3, 10.2.2.2",
			trusted:    trusted,
			want:       "10.3.3.3",
		},
		{
			name:       "trusted proxy: garbage XFF falls back to RemoteAddr",
			remoteAddr: "10.1.1.1:80",
			xff:        "not-an-ip",
			trusted:    trusted,
			want:       "10.1.1.1",
		},
		{
			name:       "trusted proxy: empty XFF uses RemoteAddr",
			remoteAddr: "10.1.1.1:80",
			xff:        "",
			trusted:    trusted,
			want:       "10.1.1.1",
		},
		{
			name:       "ipv6 remote addr",
			remoteAddr: "[2001:db8::1]:443",
			xff:        "",
			trusted:    trusted,
			want:       "2001:db8::1",
		},
		{
			name:       "remote addr without port",
			remoteAddr: "203.0.113.7",
			xff:        "",
			trusted:    nil,
			want:       "203.0.113.7",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if got := ClientIP(req, tt.trusted); got != tt.want {
				t.Errorf("ClientIP: got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIdentityKey(t *testing.T) {
	a := IdentityKey("Alice@Example.com")
	b := IdentityKey("  alice@example.com ")
	if a != b {
		t.Error("identity key must be case- and whitespace-insensitive")
	}
	if a == "alice@example.com" || len(a) != 64 {
		t.Errorf("identity key must be a hex digest, got %q", a)
	}
	if IdentityKey("bob@example.com") == a {
		t.Error("different identities must hash differently")
	}
	if IdentityKey("") != "" {
		t.Error("empty identity must yield empty key")
	}
}
