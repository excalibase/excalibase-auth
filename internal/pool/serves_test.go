package pool

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/token"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestServes_OnlyAProjectWhoseStoreWasOpened(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/vault/secrets/projects/known/credentials/auth_admin" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"host": "10.0.0.5", "port": "5432",
			"database": "app", "username": "auth_admin", "password": "secret",
		})
	}))
	defer server.Close()

	mgr := NewManager(server.URL, token.Literal("test-pat"), time.Hour)
	mgr.SetSSLMode("disable")
	mgr.poolCreator = func(context.Context, *pgxpool.Config) (*pgxpool.Pool, error) { return nil, nil }

	if mgr.Serves("known") {
		t.Fatal("no store was opened yet")
	}
	if _, err := mgr.GetStore(context.Background(), "org", "known"); err != nil {
		t.Fatalf("GetStore: %v", err)
	}
	if _, err := mgr.GetStore(context.Background(), "org", "random-path"); err == nil {
		t.Fatal("an unknown project has no credentials")
	}
	if !mgr.Serves("known") {
		t.Error("the opened project is served")
	}
	if mgr.Serves("random-path") {
		t.Error("a project the vault does not know is never served")
	}
}
