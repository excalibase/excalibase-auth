package pool

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/token"
)

func TestAuthHooksAreReadOnlyWhenTheControlPlaneSendsThem(t *testing.T) {
	hits := 0
	srv := newInfoServer(t, `{"projectId":"p1","authHooks":{"customAccessToken":"https://hooks.example.com/claims"}}`, &hits)
	defer srv.Close()
	info, err := NewManager(srv.URL, token.Literal("pat"), time.Hour).GetProjectInfo(context.Background(), "p1")
	if err != nil || info.AuthHooks == nil || info.AuthHooks.CustomAccessToken != "https://hooks.example.com/claims" ||
		info.AuthHooks.BeforeUserCreated != "" || info.AuthHooks.SendEmail != "" {
		t.Fatalf("info = %+v %v", info, err)
	}
	if (ProjectInfo{}).AuthHooks != nil {
		t.Fatal("an older control plane must read as hooks off")
	}
}

func TestHookSecretIsReadFromTheProjectsVaultPath(t *testing.T) {
	var asked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path
		switch {
		case strings.HasSuffix(r.URL.Path, "/projects/p1/auth/hooks"):
			_ = json.NewEncoder(w).Encode(map[string]string{"secret": "whsec_abc"})
		case strings.HasSuffix(r.URL.Path, "/projects/empty/auth/hooks"):
			_ = json.NewEncoder(w).Encode(map[string]string{})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	mgr := NewManager(srv.URL, token.Literal("pat"), time.Hour)
	secret, err := mgr.HookSecret(context.Background(), "p1")
	if err != nil || secret != "whsec_abc" || asked != "/vault/secrets/projects/p1/auth/hooks" {
		t.Fatalf("secret = %q, err = %v, path = %s", secret, err, asked)
	}
	if _, err := mgr.HookSecret(context.Background(), "empty"); !errors.Is(err, ErrNoHookSecret) {
		t.Fatalf("empty: err = %v", err)
	}
	if _, err := mgr.HookSecret(context.Background(), "missing"); err == nil {
		t.Fatal("a missing secret was read")
	}
	if _, err := mgr.HookSecret(context.Background(), "../p1"); err == nil {
		t.Fatal("a traversing project id was read")
	}
}
