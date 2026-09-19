package pool

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/token"
)

func newInfoServer(t *testing.T, body string, hits *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
}

func TestGetProjectInfo_DecodesVerificationSettings(t *testing.T) {
	hits := 0
	srv := newInfoServer(t, `{"projectId":"p1","projectName":"Blog","requireEmailVerification":true,"siteUrl":"https://blog.test/"}`, &hits)
	defer srv.Close()

	info, err := NewManager(srv.URL, token.Literal("pat"), time.Hour).GetProjectInfo(context.Background(), "p1")
	if err != nil {
		t.Fatalf("GetProjectInfo: %v", err)
	}
	if !info.RequireEmailVerification {
		t.Error("requireEmailVerification should decode as true")
	}
	if info.SiteURL != "https://blog.test/" {
		t.Errorf("siteUrl: got %q", info.SiteURL)
	}
}

func TestGetProjectInfo_VerificationDefaultsOffWhenAbsent(t *testing.T) {
	hits := 0
	srv := newInfoServer(t, `{"projectId":"p1","projectName":"Blog"}`, &hits)
	defer srv.Close()

	info, err := NewManager(srv.URL, token.Literal("pat"), time.Hour).GetProjectInfo(context.Background(), "p1")
	if err != nil {
		t.Fatalf("GetProjectInfo: %v", err)
	}
	// Back-compat: a control plane that doesn't know the field yet must not
	// start blocking logins.
	if info.RequireEmailVerification {
		t.Error("requireEmailVerification must default to false when absent")
	}
	if info.SiteURL != "" {
		t.Errorf("siteUrl should default empty, got %q", info.SiteURL)
	}
}

func TestProjectInfo_JSONFieldNames(t *testing.T) {
	b, _ := json.Marshal(ProjectInfo{RequireEmailVerification: true, SiteURL: "https://x.test"})
	var raw map[string]interface{}
	json.Unmarshal(b, &raw)

	if raw["requireEmailVerification"] != true {
		t.Errorf("expected requireEmailVerification key, got %v", raw)
	}
	if raw["siteUrl"] != "https://x.test" {
		t.Errorf("expected siteUrl key, got %v", raw)
	}
}
