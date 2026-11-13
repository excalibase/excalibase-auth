package pool

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/token"
)

func TestFetchCredentialsRefusesMalformedProjectIDsWithoutCallingVault(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
	}))
	defer server.Close()
	mgr := NewManager(server.URL, token.Literal("pat"), time.Hour)

	for _, id := range []string{"", "../x", "a/b", "a%2Fb", "A-Upper", "a b", "x?y=1", "-lead", "a..b", "a\n"} {
		if _, err := mgr.fetchCredentials(context.Background(), "org", id); err == nil {
			t.Errorf("id %q: expected an error", id)
		}
	}
	if calls != 0 {
		t.Fatalf("vault was called %d times for malformed ids", calls)
	}
}

func TestFetchCredentialsAcceptsRealProjectIDs(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{"host":"h"}`))
	}))
	defer server.Close()
	mgr := NewManager(server.URL, token.Literal("pat"), time.Hour)

	for _, id := range []string{"proj-jfp7kx46kb", "my_app", "project-1"} {
		if _, err := mgr.fetchCredentials(context.Background(), "org", id); err != nil {
			t.Fatalf("id %q: %v", id, err)
		}
		if want := "/vault/secrets/projects/" + id + "/credentials/auth_admin"; path != want {
			t.Fatalf("path %q, want %q", path, want)
		}
	}
}
