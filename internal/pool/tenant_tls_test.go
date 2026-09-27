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
	"github.com/jackc/pgx/v5/pgxpool"
)

func capturedConnStr(t *testing.T, mgr *Manager) string {
	t.Helper()
	var got string
	mgr.poolCreator = func(_ context.Context, connStr string) (*pgxpool.Pool, error) {
		got = connStr
		return nil, nil
	}
	if _, err := mgr.GetPool(context.Background(), "org", "project-1"); err != nil {
		t.Fatalf("GetPool: %v", err)
	}
	return got
}

func credentialServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"host": "10.0.0.5", "port": "5432",
			"database": "app", "username": "auth_admin", "password": "secret",
		})
	}))
	t.Cleanup(server.Close)
	return server
}

func TestTenantPoolRequiresTLSByDefault(t *testing.T) {
	mgr := NewManager(credentialServer(t).URL, token.Literal("pat"), time.Hour)
	connStr := capturedConnStr(t, mgr)
	if !strings.Contains(connStr, "sslmode=require") {
		t.Fatalf("tenant connection must require TLS, got %q", strings.Replace(connStr, "secret", "***", 1))
	}
}

func TestTenantPoolUsesTheConfiguredSSLMode(t *testing.T) {
	mgr := NewManager(credentialServer(t).URL, token.Literal("pat"), time.Hour)
	mgr.SetSSLMode("verify-full")
	connStr := capturedConnStr(t, mgr)
	if !strings.Contains(connStr, "sslmode=verify-full") {
		t.Fatalf("expected the configured sslmode, got %q", strings.Replace(connStr, "secret", "***", 1))
	}
}
