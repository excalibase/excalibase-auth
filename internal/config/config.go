package config

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/ratelimit"
)

type Config struct {
	Port            string
	ProvisioningURL string
	ProvisioningPAT string
	// ProvisioningPATFile is the path the PAT is delivered at, re-read on each
	// provisioning call so in-place rotation needs no restart.
	ProvisioningPATFile string
	AccessTTL           int // seconds — signed lifetime of every access token
	RefreshExpiration   int // seconds
	CORSOrigins         []string
	RateLimit           RateLimit
	// AudiencePrefix is prepended to the projectId to build the `aud` claim.
	AudiencePrefix string
	// SiteURL is the fallback base URL for links in transactional emails, used
	// when provisioning's project info carries no site URL of its own.
	SiteURL string
	// TenantDBSSLMode is the sslmode auth opens every tenant database with.
	TenantDBSSLMode string
}

// RateLimit holds the credential-endpoint throttling knobs. Per-IP and
// per-project budgets are "N requests per WindowSeconds"; the login failure
// lock is "LoginFailures failed attempts per LoginFailureWindowSeconds" keyed
// on the hashed identity. TrustedProxyCIDRs lists the proxies whose
// X-Forwarded-For header may be believed; empty means never.
type RateLimit struct {
	Enabled                   bool
	WindowSeconds             int
	RegisterPerIP             int
	LoginPerIP                int
	TokenPerIP                int
	RegisterPerProject        int
	LoginFailures             int
	LoginFailureWindowSeconds int
	TrustedProxyCIDRs         []*net.IPNet
}

// patFileEnv names the env var holding the path of the rotatable token file.
const patFileEnv = "PROVISIONING_PAT_FILE"

func Load() Config {
	accessTTL := envInt("ACCESS_TTL", 3600)
	if accessTTL <= 0 {
		// Guard against ACCESS_TTL=0 / negative producing an immediately-expired JWT.
		accessTTL = 3600
	}
	return Config{
		Port:                envOr("PORT", "24000"),
		ProvisioningURL:     envOr("PROVISIONING_URL", "http://localhost:24005/api"),
		ProvisioningPAT:     os.Getenv("PROVISIONING_PAT"),
		ProvisioningPATFile: os.Getenv(patFileEnv),
		AccessTTL:           accessTTL,
		RefreshExpiration:   envInt("REFRESH_EXPIRATION", 604800),
		CORSOrigins:         parseCORSOrigins(envOr("CORS_ORIGINS", "https://app.excalibase.io")),
		RateLimit:           loadRateLimit(),
		AudiencePrefix:      envOr("AUTH_AUD_PREFIX", auth.DefaultAudiencePrefix),
		SiteURL:             strings.TrimRight(os.Getenv("AUTH_SITE_URL"), "/"),
		TenantDBSSLMode:     tenantDBSSLMode(),
	}
}

func tenantDBSSLMode() string {
	mode, err := parseTenantDBSSLMode(os.Getenv("TENANT_DB_SSLMODE"))
	if err != nil {
		log.Fatalf("TENANT_DB_SSLMODE: %v", err)
	}
	return mode
}

// parseTenantDBSSLMode defaults to require. prefer and allow are refused:
// both fall back to plaintext without saying so.
func parseTenantDBSSLMode(raw string) (string, error) {
	switch raw {
	case "":
		return "require", nil
	case "disable", "require", "verify-ca", "verify-full":
		return raw, nil
	default:
		return "", fmt.Errorf("%q is not one of disable, require, verify-ca, verify-full", raw)
	}
}

func loadRateLimit() RateLimit {
	return RateLimit{
		Enabled:                   envBool("RATE_LIMIT_ENABLED", true),
		WindowSeconds:             envInt("RATE_LIMIT_WINDOW_SECONDS", 60),
		RegisterPerIP:             envInt("RATE_LIMIT_REGISTER_PER_IP", 5),
		LoginPerIP:                envInt("RATE_LIMIT_LOGIN_PER_IP", 10),
		TokenPerIP:                envInt("RATE_LIMIT_TOKEN_PER_IP", 30),
		RegisterPerProject:        envInt("RATE_LIMIT_REGISTER_PER_PROJECT", 60),
		LoginFailures:             envInt("RATE_LIMIT_LOGIN_FAILURES", 5),
		LoginFailureWindowSeconds: envInt("RATE_LIMIT_LOGIN_FAILURE_WINDOW_SECONDS", 900),
		TrustedProxyCIDRs:         trustedProxyCIDRs(),
	}
}

// trustedProxyCIDRs fails fast on a malformed list: silently trusting nothing
// would collapse every client behind the ingress into one shared bucket.
func trustedProxyCIDRs() []*net.IPNet {
	nets, err := ratelimit.ParseCIDRs(os.Getenv("TRUSTED_PROXY_CIDRS"))
	if err != nil {
		log.Fatalf("TRUSTED_PROXY_CIDRS: %v", err)
	}
	return nets
}

func parseCORSOrigins(raw string) []string {
	if raw == "" {
		log.Fatal("CORS_ORIGINS must be set")
	}
	if raw == "*" {
		return []string{"*"}
	}
	parts := strings.Split(raw, ",")
	origins := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			origins = append(origins, p)
		}
	}
	if len(origins) == 0 {
		log.Fatal("CORS_ORIGINS contained only empty values")
	}
	return origins
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envBool accepts the strconv.ParseBool spellings (true/false/1/0/t/f/...);
// anything else keeps the fallback.
func envBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}
