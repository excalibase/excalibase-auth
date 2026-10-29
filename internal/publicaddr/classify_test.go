package publicaddr

import (
	"errors"
	"net/netip"
	"testing"
)

func TestClassifyAddr_BlocksInternalRanges(t *testing.T) {
	blocked := []struct{ name, addr string }{
		{"v4 loopback", "127.0.0.1"},
		{"v4 loopback high", "127.255.255.254"},
		{"v4 unspecified", "0.0.0.0"},
		{"v4 this-network", "0.1.2.3"},
		{"v4 rfc1918 10/8", "10.1.2.3"},
		{"v4 rfc1918 172.16/12", "172.16.0.1"},
		{"v4 rfc1918 172.31", "172.31.255.255"},
		{"v4 rfc1918 192.168/16", "192.168.0.5"},
		{"v4 link-local", "169.254.10.10"},
		{"v4 cloud metadata", "169.254.169.254"},
		{"v4 cgnat 100.64/10", "100.64.0.1"},
		{"v4 alibaba metadata", "100.100.100.200"},
		{"v4 ietf protocol 192.0.0/24", "192.0.0.192"},
		{"v4 benchmarking 198.18/15", "198.18.0.1"},
		{"v4 reserved 240/4", "240.0.0.1"},
		{"v4 broadcast", "255.255.255.255"},
		{"v4 multicast", "224.0.0.1"},
		{"v6 loopback", "::1"},
		{"v6 unspecified", "::"},
		{"v6 ula fc00::/7 low", "fc00::1"},
		{"v6 ula fd", "fd12:3456::1"},
		{"v6 aws metadata", "fd00:ec2::254"},
		{"v6 link-local fe80::/10", "fe80::1"},
		{"v6 link-local febf", "febf::1"},
		{"v6 site-local deprecated fec0::/10", "fec0::1"},
		{"v6 multicast", "ff02::1"},
		{"v6 v4-mapped loopback", "::ffff:127.0.0.1"},
		{"v6 v4-mapped private", "::ffff:10.0.0.1"},
		{"v6 v4-mapped metadata", "::ffff:169.254.169.254"},
		{"v6 v4-compatible deprecated", "::10.0.0.1"},
		{"v6 nat64 embedding private", "64:ff9b::10.0.0.1"},
		{"v6 nat64 embedding metadata", "64:ff9b::a9fe:a9fe"},
		{"v6 local-use nat64 64:ff9b:1::/48", "64:ff9b:1::808:808"},
		{"v6 6to4 embedding private", "2002:0a00:0001::1"},
		{"v6 6to4 embedding metadata", "2002:a9fe:a9fe::1"},
		{"v6 teredo tunnel", "2001:0:4136:e378:8000:63bf:3fff:fdd2"},
		{"v6 discard-only 100::/64", "100::1"},
	}
	for _, tc := range blocked {
		t.Run(tc.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tc.addr)
			err := ClassifyAddr(addr)
			if !errors.Is(err, ErrInternalAddress) {
				t.Fatalf("ClassifyAddr(%s) = %v, want ErrInternalAddress", tc.addr, err)
			}
		})
	}
}

func TestClassifyAddr_AllowsPublicRanges(t *testing.T) {
	public := []string{
		"8.8.8.8",
		"1.1.1.1",
		"203.0.113.10",
		"52.94.76.1",
		"172.32.0.1",  // just outside 172.16/12
		"100.128.0.1", // just outside 100.64/10
		"2001:4860:4860::8888",
		"2606:4700:4700::1111",
		"::ffff:8.8.8.8", // mapped public unwraps to public
		"64:ff9b::8.8.8.8",
		"2002:0808:0808::1", // 6to4 embedding public
	}
	for _, s := range public {
		if err := ClassifyAddr(netip.MustParseAddr(s)); err != nil {
			t.Errorf("ClassifyAddr(%s) = %v, want nil", s, err)
		}
	}
}
