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
	"github.com/excalibase/auth/internal/handler"
	custommw "github.com/excalibase/auth/internal/middleware"
	"github.com/excalibase/auth/internal/migrate"
	"github.com/excalibase/auth/internal/pool"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	cfg := config.Load()

	if cfg.ProvisioningPAT == "" {
		log.Fatal("PROVISIONING_PAT environment variable is required")
	}

	// Fetch signing key from vault
	privateKeyPEM, err := fetchSigningKey(cfg.ProvisioningURL, cfg.ProvisioningPAT)
	if err != nil {
		log.Fatalf("Failed to fetch signing key from vault: %v", err)
	}

	// JWT service
	jwtService, err := auth.NewJWTService(privateKeyPEM, "excalibase", cfg.JWTExpiration)
	if err != nil {
		log.Fatalf("Failed to init JWT service: %v", err)
	}

	// Pool manager (multi-tenant connection cache)
	poolMgr := pool.NewManager(cfg.ProvisioningURL, cfg.ProvisioningPAT, 1*time.Hour)
	poolMgr.SetMigrator(func(ctx context.Context, connStr string) error {
		return migrate.Run(connStr)
	})

	// Handler
	authHandler := handler.NewAuthHandler(poolMgr, jwtService, cfg.RefreshExpiration)

	// Router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(custommw.SecurityHeaders)
	r.Use(custommw.CORS(cfg.CORSOrigins))

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	r.Route("/auth", authHandler.Routes)

	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("excalibase-auth starting on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func fetchSigningKey(provisioningURL, pat string) (string, error) {
	url := provisioningURL + "/vault/secrets/pki/signing/private"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+pat)

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
