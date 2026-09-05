package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/pool"
	"github.com/go-chi/chi/v5"
)

// setupAuthzRouter builds the same router as setupUnitRouter but also returns the
// JWTService so tests can mint valid tokens for specific projects/scopes. The
// pool manager points at an unreachable vault, so a request that survives the
// authz checks lands on the DB layer and yields 503 — letting us distinguish
// "passed authorization" (503) from "blocked by authorization" (403).
func setupAuthzRouter(t *testing.T) (chi.Router, *auth.JWTService) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))

	jwtSvc, _ := auth.NewJWTService(keyPEM, "excalibase", 3600)
	mgr := pool.NewManager("http://127.0.0.1:1", "fake-pat", time.Hour)
	h := NewAuthHandler(mgr, jwtSvc, 900, 604800)

	r := chi.NewRouter()
	r.Route("/auth", h.Routes)
	return r, jwtSvc
}

func mintToken(t *testing.T, svc *auth.JWTService, projectID, scope string) string {
	t.Helper()
	tok, err := svc.Sign(auth.Claims{
		Sub:       "alice@test.com",
		UserID:    7,
		ProjectID: projectID,
		Role:      "user",
		Scope:     scope,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return tok
}

// (a) A token whose ProjectID matches the URL project must pass the authz checks
// and reach the DB layer (503 here, since the test vault is unreachable). It must
// NOT be rejected with 401/403.
func TestAPIKey_Create_SameProjectPassesAuthz(t *testing.T) {
	r, svc := setupAuthzRouter(t)
	token := mintToken(t, svc, "test-project", "authenticated")

	body := `{"name":"ci","keyType":"publishable"}`
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/api-keys/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code == 401 || w.Code == 403 {
		t.Fatalf("same-project authenticated token must pass authz, got %d", w.Code)
	}
	if w.Code != 503 {
		t.Errorf("expected 503 (authz passed, DB unreachable), got %d", w.Code)
	}
}

// (b) A token for project A calling project B's URL must be forbidden.
func TestAPIKey_Create_CrossProjectForbidden(t *testing.T) {
	r, svc := setupAuthzRouter(t)
	token := mintToken(t, svc, "project-a", "authenticated")

	body := `{"name":"ci","keyType":"publishable"}`
	req := httptest.NewRequest("POST", "/auth/test-org/project-b/api-keys/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("cross-project token must be 403, got %d", w.Code)
	}
	assertErrorContains(t, w.Body.Bytes(), "token project mismatch")
}

func TestAPIKey_List_CrossProjectForbidden(t *testing.T) {
	r, svc := setupAuthzRouter(t)
	token := mintToken(t, svc, "project-a", "authenticated")

	req := httptest.NewRequest("GET", "/auth/test-org/project-b/api-keys/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("cross-project list must be 403, got %d", w.Code)
	}
}

func TestAPIKey_Revoke_CrossProjectForbidden(t *testing.T) {
	r, svc := setupAuthzRouter(t)
	token := mintToken(t, svc, "project-a", "authenticated")

	req := httptest.NewRequest("DELETE", "/auth/test-org/project-b/api-keys/42", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("cross-project revoke must be 403, got %d", w.Code)
	}
}

// (c) A public-scope (publishable / browser) token must not manage api keys even
// for its own project.
func TestAPIKey_Create_PublicScopeForbidden(t *testing.T) {
	r, svc := setupAuthzRouter(t)
	token := mintToken(t, svc, "test-project", "public")

	body := `{"name":"ci","keyType":"publishable"}`
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/api-keys/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("public-scope token must be 403 on CreateAPIKey, got %d", w.Code)
	}
	assertErrorContains(t, w.Body.Bytes(), "scope")
}

func TestAPIKey_List_PublicScopeForbidden(t *testing.T) {
	r, svc := setupAuthzRouter(t)
	token := mintToken(t, svc, "test-project", "public")

	req := httptest.NewRequest("GET", "/auth/test-org/test-project/api-keys/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("public-scope token must be 403 on ListAPIKeys, got %d", w.Code)
	}
}

// A service-scope token (secret key) is allowed to manage keys for its project.
func TestAPIKey_Create_ServiceScopeSameProjectPassesAuthz(t *testing.T) {
	r, svc := setupAuthzRouter(t)
	token := mintToken(t, svc, "test-project", "service")

	body := `{"name":"ci","keyType":"secret"}`
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/api-keys/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code == 401 || w.Code == 403 {
		t.Fatalf("service-scope same-project token must pass authz, got %d", w.Code)
	}
}

// (d) /validate with a token for project A against project B must report not-valid.
func TestValidate_CrossProjectNotValid(t *testing.T) {
	r, svc := setupAuthzRouter(t)
	token := mintToken(t, svc, "project-a", "authenticated")

	body := `{"token":"` + token + `"}`
	req := httptest.NewRequest("POST", "/auth/test-org/project-b/validate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("validate returns 200 with valid=false body, got %d", w.Code)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if valid, _ := out["valid"].(bool); valid {
		t.Fatalf("cross-project token must be valid=false, got %v", out)
	}
}

// /validate with a matching-project token keeps the success shape.
func TestValidate_SameProjectStillValid(t *testing.T) {
	r, svc := setupAuthzRouter(t)
	token := mintToken(t, svc, "test-project", "authenticated")

	body := `{"token":"` + token + `"}`
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/validate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var out map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if valid, _ := out["valid"].(bool); !valid {
		t.Fatalf("same-project token must be valid=true, got %v", out)
	}
	if out["projectId"] != "test-project" {
		t.Errorf("projectId in response: got %v, want test-project", out["projectId"])
	}
}

func assertErrorContains(t *testing.T, body []byte, want string) {
	t.Helper()
	var out map[string]interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal error body: %v", err)
	}
	msg, _ := out["error"].(string)
	if !strings.Contains(msg, want) {
		t.Errorf("error body %q should contain %q", msg, want)
	}
}
