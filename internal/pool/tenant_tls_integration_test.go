package pool

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/token"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// A tenant database that cannot encrypt is refused, not dialled in plaintext.
func TestIntegration_TenantPoolRefusesADatabaseThatCannotEncrypt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("app"), postgres.WithUsername("auth_admin"), postgres.WithPassword("secret"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(30*time.Second)))
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(ctx) })
	host, _ := pg.Host(ctx)
	port, _ := pg.MappedPort(ctx, "5432")

	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"host": host, "port": port.Port(), "database": "app", "username": "auth_admin", "password": "secret",
		})
	}))
	t.Cleanup(vault.Close)

	mgr := NewManager(vault.URL, token.Literal("pat"), time.Hour)
	pool, err := mgr.GetPool(ctx, "org", "tenant-a")
	if err == nil {
		err = pool.Ping(ctx)
		pool.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "refused TLS") {
		t.Fatalf("expected the plaintext-only database to be refused for TLS, got %v", err)
	}

	plain := NewManager(vault.URL, token.Literal("pat"), time.Hour)
	plain.SetSSLMode("disable")
	pool, err = plain.GetPool(ctx, "org", "tenant-a")
	if err != nil {
		t.Fatalf("GetPool with disable: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("the same database with sslmode=disable should answer, so the refusal above was TLS: %v", err)
	}
}
