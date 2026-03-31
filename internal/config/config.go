package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port              string
	ProvisioningURL   string
	ProvisioningPAT   string
	JWTExpiration     int // seconds
	RefreshExpiration int // seconds
}

func Load() Config {
	return Config{
		Port:              envOr("PORT", "24000"),
		ProvisioningURL:   envOr("PROVISIONING_URL", "http://localhost:24005/api"),
		ProvisioningPAT:   os.Getenv("PROVISIONING_PAT"),
		JWTExpiration:     envInt("JWT_EXPIRATION", 86400),
		RefreshExpiration: envInt("REFRESH_EXPIRATION", 604800),
	}
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
