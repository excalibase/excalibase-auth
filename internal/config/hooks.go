package config

import (
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
)

// Hooks shapes calls to projects' auth hooks (EXC-662).
type Hooks struct {
	// DenyCIDRs are refused on top of every internal range, such as the
	// platform's own public edge.
	DenyCIDRs []netip.Prefix
	// CAFile adds roots that hook servers may be verified against.
	CAFile string
}

func loadHooks() Hooks {
	deny, err := parseHookDenyCIDRs(os.Getenv("AUTH_HOOKS_DENY_CIDRS"))
	if err != nil {
		log.Fatalf("AUTH_HOOKS_DENY_CIDRS: %v", err)
	}
	return Hooks{DenyCIDRs: deny, CAFile: strings.TrimSpace(os.Getenv("AUTH_HOOKS_CA_FILE"))}
}

// parseHookDenyCIDRs reads comma-separated CIDRs; a bad one fails start-up
// rather than leaving a range reachable.
func parseHookDenyCIDRs(raw string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not a CIDR", part)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}
