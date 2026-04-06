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
	JWTExpiration     int // seconds
	RefreshExpiration int // seconds
	CORSOrigins       []string
}

func Load() Config {
	return Config{
		Port:              envOr("PORT", "24000"),
		ProvisioningURL:   envOr("PROVISIONING_URL", "http://localhost:24005/api"),
		ProvisioningPAT:   os.Getenv("PROVISIONING_PAT"),
		JWTExpiration:     envInt("JWT_EXPIRATION", 86400),
		RefreshExpiration: envInt("REFRESH_EXPIRATION", 604800),
		CORSOrigins:       parseCORSOrigins(envOr("CORS_ORIGINS", "https://app.excalibase.io")),
	}
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
