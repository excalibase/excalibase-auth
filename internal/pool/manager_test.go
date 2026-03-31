package pool

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestFetchCredentials(t *testing.T) {
	creds := map[string]string{
		"host": "10.0.0.5", "port": "5432",
		"database": "app", "username": "auth_admin", "password": "secret",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-pat" {
			t.Errorf("expected Bearer test-pat, got %s", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/vault/secrets/projects/my-app/credentials/auth_admin" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(creds)
	}))
	defer server.Close()

	mgr := NewManager(server.URL, "test-pat", time.Hour)

	got, err := mgr.fetchCredentials(context.Background(), "my-app")
	if err != nil {
		t.Fatalf("fetchCredentials: %v", err)
	}
	if got["host"] != "10.0.0.5" {
		t.Errorf("host: got %s", got["host"])
	}
	if got["username"] != "auth_admin" {
		t.Errorf("username: got %s", got["username"])
	}
}

func TestGetPoolCaches(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(map[string]string{
			"host": "10.0.0.5", "port": "5432",
			"database": "app", "username": "auth_admin", "password": "secret",
		})
	}))
	defer server.Close()

	mgr := NewManager(server.URL, "test-pat", time.Hour)
	// Mock pool creator since we can't connect to real PG
	mgr.poolCreator = func(ctx context.Context, connStr string) (*pgxpool.Pool, error) {
		// Return nil pool — we're testing cache logic, not PG connection
		return nil, nil
	}

	ctx := context.Background()
	mgr.GetPool(ctx, "project-1")
	mgr.GetPool(ctx, "project-1") // should be cached

	if callCount != 1 {
		t.Errorf("expected 1 vault call (cached), got %d", callCount)
	}
}

func TestGetPoolTTLExpiry(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(map[string]string{
			"host": "10.0.0.5", "port": "5432",
			"database": "app", "username": "auth_admin", "password": "secret",
		})
	}))
	defer server.Close()

	mgr := NewManager(server.URL, "test-pat", 1*time.Millisecond) // very short TTL
	mgr.poolCreator = func(ctx context.Context, connStr string) (*pgxpool.Pool, error) {
		return nil, nil
	}

	ctx := context.Background()
	mgr.GetPool(ctx, "project-1")
	time.Sleep(5 * time.Millisecond)
	mgr.GetPool(ctx, "project-1") // TTL expired, should re-fetch

	if callCount != 2 {
		t.Errorf("expected 2 vault calls (TTL expired), got %d", callCount)
	}
}

func TestFetchCredentials_VaultError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer server.Close()

	mgr := NewManager(server.URL, "test-pat", time.Hour)
	_, err := mgr.fetchCredentials(context.Background(), "bad-project")
	if err == nil {
		t.Fatal("expected error for vault 503")
	}
}
