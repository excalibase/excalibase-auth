package config

import (
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/ratelimit"
)

type Config struct {
	Port              string
	ProvisioningURL   string
	ProvisioningPAT   string
	JWTExpiration     int // seconds — legacy alias, kept for back-compat
	AccessTTL         int // seconds — access-token lifetime used by /token + legacy endpoints
	RefreshExpiration int // seconds
	CORSOrigins       []string
	RateLimit         RateLimit
	// AudiencePrefix is prepended to the projectId to build the `aud` claim.
	AudiencePrefix string
	// SiteURL is the fallback base URL for links in transactional emails, used
	// when provisioning's project info carries no site URL of its own.
	SiteURL string
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

func Load() Config {
	jwtExp := envInt("JWT_EXPIRATION", 86400)
	// AccessTTL fallback chain: ACCESS_TTL env → JWT_EXPIRATION (if explicitly set
	// by the operator) → 3600. Fresh installs get the new secure 1h default; legacy
	// deployments that pinned JWT_EXPIRATION keep their historical value.
	defaultAccess := 3600
	if os.Getenv("JWT_EXPIRATION") != "" {
		defaultAccess = jwtExp
	}
	accessTTL := envInt("ACCESS_TTL", defaultAccess)
	if accessTTL <= 0 {
		// Guard against ACCESS_TTL=0 / negative producing an immediately-expired JWT.
		accessTTL = 3600
	}
	return Config{
		Port:              envOr("PORT", "24000"),
		ProvisioningURL:   envOr("PROVISIONING_URL", "http://localhost:24005/api"),
		ProvisioningPAT:   provisioningPAT(),
		JWTExpiration:     jwtExp,
		AccessTTL:         accessTTL,
		RefreshExpiration: envInt("REFRESH_EXPIRATION", 604800),
		CORSOrigins:       parseCORSOrigins(envOr("CORS_ORIGINS", "https://app.excalibase.io")),
		RateLimit:         loadRateLimit(),
		AudiencePrefix:    envOr("AUTH_AUD_PREFIX", auth.DefaultAudiencePrefix),
		SiteURL:           strings.TrimRight(os.Getenv("AUTH_SITE_URL"), "/"),
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

// provisioningPAT resolves the provisioning PAT from PROVISIONING_PAT, falling
// back to the trimmed contents of the file at PROVISIONING_PAT_FILE. The file
// path lets a bootstrap step hand the PAT to this distroless (shell-less)
// service via a shared volume instead of injecting env after start.
func provisioningPAT() string {
	if v := os.Getenv("PROVISIONING_PAT"); v != "" {
		return v
	}
	if path := os.Getenv("PROVISIONING_PAT_FILE"); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
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
