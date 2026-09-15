package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ParseCIDRs parses a comma-separated list of CIDRs (bare IPs are accepted as
// /32 or /128). An empty string yields no trusted proxies, which is the safe
// default: X-Forwarded-For is then never consulted.
func ParseCIDRs(raw string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			part = hostCIDR(part)
		}
		_, network, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy cidr %q: %w", part, err)
		}
		nets = append(nets, network)
	}
	return nets, nil
}

func hostCIDR(ip string) string {
	if strings.Contains(ip, ":") {
		return ip + "/128"
	}
	return ip + "/32"
}

// ClientIP returns the address to rate-limit on. RemoteAddr is authoritative
// unless it belongs to a trusted proxy, in which case X-Forwarded-For is
// walked from the right (the hop appended by our nearest proxy) towards the
// left, skipping further trusted proxies; the first untrusted hop is the
// client. Values injected by the client at the left of the list are therefore
// never trusted. Any parse failure falls back to RemoteAddr.
func ClientIP(r *http.Request, trusted []*net.IPNet) string {
	remote := remoteIP(r.RemoteAddr)
	if len(trusted) == 0 || !contains(trusted, net.ParseIP(remote)) {
		return remote
	}
	hops := forwardedHops(r.Header.Get("X-Forwarded-For"))
	if len(hops) == 0 {
		return remote
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if !contains(trusted, hops[i]) {
			return hops[i].String()
		}
	}
	return hops[0].String()
}

// forwardedHops parses an X-Forwarded-For value. It returns nil if any entry
// fails to parse so a partially forged header cannot steer the result.
func forwardedHops(header string) []net.IP {
	if strings.TrimSpace(header) == "" {
		return nil
	}
	parts := strings.Split(header, ",")
	hops := make([]net.IP, 0, len(parts))
	for _, part := range parts {
		ip := net.ParseIP(strings.TrimSpace(part))
		if ip == nil {
			return nil
		}
		hops = append(hops, ip)
	}
	return hops
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func contains(nets []*net.IPNet, ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, network := range nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// IdentityKey derives a stable, non-reversible limiter key from a login
// identity (email/username). The digest is what gets stored and what any
// diagnostic could safely reference; the raw identity never leaves the
// request. Empty input yields an empty key so callers can skip the check.
func IdentityKey(identity string) string {
	normalized := strings.ToLower(strings.TrimSpace(identity))
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}
