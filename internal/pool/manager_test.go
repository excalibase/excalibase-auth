package pool

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/token"
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

	mgr := NewManager(server.URL, token.Literal("test-pat"), time.Hour)

	got, err := mgr.fetchCredentials(context.Background(), "my-org", "my-app")
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

	mgr := NewManager(server.URL, token.Literal("test-pat"), time.Hour)
	// Mock pool creator since we can't connect to real PG
	mgr.poolCreator = func(ctx context.Context, connStr string) (*pgxpool.Pool, error) {
		// Return nil pool — we're testing cache logic, not PG connection
		return nil, nil
	}

	ctx := context.Background()
	mgr.GetPool(ctx, "my-org", "project-1")
	mgr.GetPool(ctx, "my-org", "project-1") // should be cached

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

	mgr := NewManager(server.URL, token.Literal("test-pat"), 1*time.Millisecond) // very short TTL
	mgr.poolCreator = func(ctx context.Context, connStr string) (*pgxpool.Pool, error) {
		return nil, nil
	}

	ctx := context.Background()
	mgr.GetPool(ctx, "my-org", "project-1")
	time.Sleep(5 * time.Millisecond)
	mgr.GetPool(ctx, "my-org", "project-1") // TTL expired, should re-fetch

	if callCount != 2 {
		t.Errorf("expected 2 vault calls (TTL expired), got %d", callCount)
	}
}

func TestFetchCredentials_VaultError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer server.Close()

	mgr := NewManager(server.URL, token.Literal("test-pat"), time.Hour)
	_, err := mgr.fetchCredentials(context.Background(), "my-org", "bad-project")
	if err == nil {
		t.Fatal("expected error for vault 503")
	}
}

func TestFetchCredentials_UsesRotatedTokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(path, []byte("first-pat\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		json.NewEncoder(w).Encode(map[string]string{"host": "10.0.0.5"})
	}))
	defer server.Close()

	// interval 0: every call re-checks the file, so the test never sleeps.
	mgr := NewManager(server.URL, token.NewFileSource(path, "", token.WithInterval(0)), time.Hour)

	if _, err := mgr.fetchCredentials(context.Background(), "my-org", "my-app"); err != nil {
		t.Fatalf("first fetch: %v", err)
	}

	if err := os.WriteFile(path, []byte("rotated-pat-value\n"), 0o600); err != nil {
		t.Fatalf("rotate token file: %v", err)
	}

	if _, err := mgr.fetchCredentials(context.Background(), "my-org", "my-app"); err != nil {
		t.Fatalf("second fetch: %v", err)
	}

	want := []string{"Bearer first-pat", "Bearer rotated-pat-value"}
	if len(seen) != len(want) {
		t.Fatalf("requests: got %d, want %d", len(seen), len(want))
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("request %d authorization: got %q, want %q", i, seen[i], want[i])
		}
	}
}

func TestGetProjectInfo_UsesCurrentToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(path, []byte("info-pat"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	got := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		json.NewEncoder(w).Encode(ProjectInfo{ProjectID: "my-app", OrgSlug: "my-org"})
	}))
	defer server.Close()

	mgr := NewManager(server.URL, token.NewFileSource(path, "", token.WithInterval(0)), time.Hour)
	if _, err := mgr.GetProjectInfo(context.Background(), "my-app"); err != nil {
		t.Fatalf("GetProjectInfo: %v", err)
	}

	if got != "Bearer info-pat" {
		t.Errorf("authorization: got %q, want %q", got, "Bearer info-pat")
	}
}
