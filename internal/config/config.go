package config

import (
	"log"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port              string
	ProvisioningURL   string
	ProvisioningPAT   string
	JWTExpiration     int // seconds — legacy alias, kept for back-compat
	AccessTTL         int // seconds — access-token lifetime used by /token + legacy endpoints
	RefreshExpiration int // seconds
	CORSOrigins       []string
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
	}
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

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}
