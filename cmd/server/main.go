package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/config"
	"github.com/excalibase/auth/internal/email"
	"github.com/excalibase/auth/internal/handler"
	"github.com/excalibase/auth/internal/metrics"
	custommw "github.com/excalibase/auth/internal/middleware"
	"github.com/excalibase/auth/internal/migrate"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/token"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	cfg := config.Load()

	// The token file is rotated in place without a restart, so the token is read
	// per call rather than captured here. When PROVISIONING_PAT_FILE is set it
	// wins over PROVISIONING_PAT (which then only seeds the value until the
	// first successful read); with neither set, Get fails fast below instead of
	// letting an empty token reach a request.
	tokens := token.NewFileSource(cfg.ProvisioningPATFile, cfg.ProvisioningPAT)
	if _, err := tokens.Get(); err != nil {
		log.Fatalf("provisioning token: %v (set PROVISIONING_PAT or PROVISIONING_PAT_FILE)", err)
	}

	// Fetch signing key from vault
	privateKeyPEM, err := fetchSigningKey(cfg.ProvisioningURL, tokens)
	if err != nil {
		log.Fatalf("Failed to fetch signing key from vault: %v", err)
	}

	// JWT service
	jwtService, err := auth.NewJWTService(privateKeyPEM, "excalibase", cfg.JWTExpiration)
	if err != nil {
		log.Fatalf("Failed to init JWT service: %v", err)
	}
	jwtService.SetAudiencePrefix(cfg.AudiencePrefix)

	// Pool manager (multi-tenant connection cache)
	poolMgr := pool.NewManager(cfg.ProvisioningURL, tokens, 1*time.Hour)
	poolMgr.SetMigrator(func(ctx context.Context, connStr string) error {
		return migrate.Run(connStr)
	})

	// Handler
	authHandler := handler.NewAuthHandler(poolMgr, jwtService, cfg.AccessTTL, cfg.RefreshExpiration)
	if cfg.RateLimit.Enabled {
		authHandler.WithRateLimits(custommw.NewRateLimits(custommw.RateLimitConfigFrom(cfg.RateLimit)))
	} else {
		log.Printf("rate limiting disabled (RATE_LIMIT_ENABLED=false)")
	}

	// Transactional mail goes out through provisioning, which owns the provider
	// and the templates; auth carries no mail SDK of its own. email.Client
	// consults tokens on every Send, so it also survives a PROVISIONING_PAT_FILE
	// rotation without a restart, same as the vault fetch and pool manager above.
	authHandler.SetEmail(email.NewClient(cfg.ProvisioningURL, tokens), cfg.SiteURL)

	// Router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(custommw.SecurityHeaders)
	r.Use(custommw.CORS(cfg.CORSOrigins))
	r.Use(metrics.Middleware)

	r.Handle("/metrics", metrics.Handler())

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	r.Get("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwtService.PublicKeyJWKS())
	})

	r.Route("/auth", authHandler.Routes)

	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("excalibase-auth starting on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func fetchSigningKey(provisioningURL string, tokens token.Source) (string, error) {
	url := provisioningURL + "/vault/secrets/pki/signing/private"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	tok, err := tokens.Get()
	if err != nil {
		return "", fmt.Errorf("provisioning token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("vault returned %d", resp.StatusCode)
	}

	var data map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}

	key, ok := data["key"]
	if !ok || key == "" {
		return "", fmt.Errorf("signing key not found in vault response")
	}
	return key, nil
}
