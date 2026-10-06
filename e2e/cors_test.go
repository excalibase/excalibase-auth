//go:build e2e

package e2e

import (
	"net/http"
	"testing"
)

// The mock provisioning lists corsAppOrigin on corsProject's allowlist.
const (
	corsProject   = "proj-cors-e2e"
	corsAppOrigin = "https://examples-cors.apps.e2e.test"
)

func preflight(t *testing.T, path, origin string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodOptions, authServerURL+path, nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type,x-excalibase-publishable-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS %s: %v", path, err)
	}
	resp.Body.Close()
	return resp
}

// A page on the project's app URL can run the browser sign-in exchange; other
// origins and other projects cannot; Studio keeps its platform grant.
func TestE2E_ProjectRoutesAnswerCORSFromTheProjectsAllowlist(t *testing.T) {
	tokenPath := "/auth/default/" + corsProject + "/token"

	resp := preflight(t, tokenPath, corsAppOrigin)
	if resp.StatusCode != http.StatusNoContent || resp.Header.Get("Access-Control-Allow-Origin") != corsAppOrigin {
		t.Errorf("app origin: %d %q, want 204 %s", resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"), corsAppOrigin)
	}

	if resp := preflight(t, tokenPath, "https://evil.e2e.test"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("unlisted origin: %d, want 403", resp.StatusCode)
	}
	if resp := preflight(t, "/auth/default/proj-other/token", corsAppOrigin); resp.StatusCode != http.StatusForbidden {
		t.Errorf("other project: %d, want 403", resp.StatusCode)
	}

	studio := preflight(t, tokenPath, "https://app.excalibase.io")
	if studio.StatusCode != http.StatusNoContent || studio.Header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("studio: %d credentials=%q, want 204 true", studio.StatusCode, studio.Header.Get("Access-Control-Allow-Credentials"))
	}
}
