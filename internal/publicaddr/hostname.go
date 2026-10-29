package publicaddr

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ErrInvalidHost marks a host that is not a single public hostname or IP literal.
var ErrInvalidHost = errors.New("host must be a single public hostname or IP address")

const (
	maxHostnameLen = 253
	maxLabelLen    = 63
)

// internalSuffixes are names that never denote a target outside the platform.
var internalSuffixes = []string{".localhost", ".internal", ".local", ".localdomain", ".home.arpa"}

// ValidateHostSyntax accepts exactly one hostname (at least two labels) or one
// IP literal, optionally bracketed. Zone ids, ports, paths, multi-host lists
// and reserved internal suffixes are refused.
func ValidateHostSyntax(host string) error {
	if _, ok := parseLiteral(host); ok {
		return nil
	}
	if strings.HasPrefix(host, "[") || looksLikeAddress(host) {
		return fmt.Errorf("%w: %q is not a valid IP literal", ErrInvalidHost, host)
	}
	name := canonicalName(host)
	if name == "" || len(name) > maxHostnameLen || !strings.Contains(name, ".") {
		return fmt.Errorf("%w: %q", ErrInvalidHost, host)
	}
	for _, suffix := range internalSuffixes {
		if strings.HasSuffix(name, suffix) {
			return fmt.Errorf("%w: %q resolves inside the platform network", ErrInvalidHost, host)
		}
	}
	for _, label := range strings.Split(name, ".") {
		if !validLabel(label) {
			return fmt.Errorf("%w: %q", ErrInvalidHost, host)
		}
	}
	return nil
}

// looksLikeAddress catches malformed literals (zone ids, mixed notation) so
// they are not mistaken for hostnames.
func looksLikeAddress(host string) bool {
	return strings.ContainsAny(host, ":%")
}

func validLabel(label string) bool {
	if label == "" || len(label) > maxLabelLen || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, r := range label {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// parseLiteral parses "a.b.c.d", "x::y" or "[x::y]". Literals with a zone id
// are not accepted.
func parseLiteral(host string) (netip.Addr, bool) {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.HasPrefix(host, "[") != strings.HasSuffix(host, "]") {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr, true
}

// canonicalName lower-cases a hostname and drops the trailing dot.
func canonicalName(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}
