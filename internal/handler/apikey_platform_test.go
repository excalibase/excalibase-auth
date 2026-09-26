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

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/token"
)

// setupPlatformKeyRouter is setupAuthzRouter plus the signing key, so a test
// can sign what the control plane signs: it holds the same platform key.
func setupPlatformKeyRouter(t *testing.T) (chi.Router, *ecdsa.PrivateKey, *auth.JWTService) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	jwtSvc, _ := auth.NewJWTService(keyPEM, "excalibase", 3600)
	mgr := pool.NewManager("http://127.0.0.1:1", token.Literal("fake-pat"), time.Hour)
	r := chi.NewRouter()
	r.Route("/auth", NewAuthHandler(mgr, jwtSvc, 604800).Routes)
	return r, priv, jwtSvc
}

type keyAdminToken struct {
	projectID string
	audience  string
	tokenUse  string
	lifetime  time.Duration
}

func signKeyAdmin(t *testing.T, key *ecdsa.PrivateKey, spec keyAdminToken) string {
	t.Helper()
	now := time.Now()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "excalibase", "sub": "svc-provisioning", "projectId": spec.projectID,
		"aud": []string{spec.audience}, "token_use": spec.tokenUse,
		"iat": now.Unix(), "exp": now.Add(spec.lifetime).Unix(),
	}).SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func validKeyAdmin(projectID string) keyAdminToken {
	return keyAdminToken{projectID: projectID, audience: auth.KeyAdminAudience(projectID), tokenUse: auth.TokenUseKeyAdmin, lifetime: time.Minute}
}

var keyRoutes = []struct{ method, path, body string }{
	{"POST", "/auth/test-org/test-project/api-keys/", `{"name":"web","keyType":"publishable"}`},
	{"GET", "/auth/test-org/test-project/api-keys/", ""},
	{"DELETE", "/auth/test-org/test-project/api-keys/42", ""},
}

func callKeyRoutes(t *testing.T, r chi.Router, bearer string) []int {
	t.Helper()
	codes := make([]int, 0, len(keyRoutes))
	for _, tc := range keyRoutes {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		codes = append(codes, w.Code)
	}
	return codes
}

// The control plane manages a project's keys on a developer's behalf with a
// short token only it can sign. Getting past authorization lands on the
// (unreachable) project database, which answers 503.
func TestAPIKey_PlatformKeyAdminTokenIsAccepted(t *testing.T) {
	r, key, _ := setupPlatformKeyRouter(t)
	for i, code := range callKeyRoutes(t, r, signKeyAdmin(t, key, validKeyAdmin("test-project"))) {
		if code != 503 {
			t.Errorf("%s %s: got %d, want 503 (past authorization)", keyRoutes[i].method, keyRoutes[i].path, code)
		}
	}
}

func TestAPIKey_PlatformKeyAdminTokenIsRefusedWhenMisshapen(t *testing.T) {
	r, key, _ := setupPlatformKeyRouter(t)
	cases := map[string]keyAdminToken{
		"another project":       validKeyAdmin("other-project"),
		"engine audience":       {projectID: "test-project", audience: "excalibase:test-project", tokenUse: auth.TokenUseKeyAdmin, lifetime: time.Minute},
		"another project's aud": {projectID: "test-project", audience: auth.KeyAdminAudience("other-project"), tokenUse: auth.TokenUseKeyAdmin, lifetime: time.Minute},
		"access token_use":      {projectID: "test-project", audience: auth.KeyAdminAudience("test-project"), tokenUse: auth.TokenUseAccess, lifetime: time.Minute},
		"long-lived":            {projectID: "test-project", audience: auth.KeyAdminAudience("test-project"), tokenUse: auth.TokenUseKeyAdmin, lifetime: time.Hour},
	}
	for name, spec := range cases {
		for i, code := range callKeyRoutes(t, r, signKeyAdmin(t, key, spec)) {
			if code != 403 {
				t.Errorf("%s: %s %s got %d, want 403", name, keyRoutes[i].method, keyRoutes[i].path, code)
			}
		}
	}
}

// Holders of a secret key keep managing keys as before.
func TestAPIKey_ServiceScopeAccessTokenStillManagesKeys(t *testing.T) {
	r, _, svc := setupPlatformKeyRouter(t)
	for i, code := range callKeyRoutes(t, r, mintToken(t, svc, "test-project", "service")) {
		if code != 503 {
			t.Errorf("%s %s: got %d, want 503", keyRoutes[i].method, keyRoutes[i].path, code)
		}
	}
}

// /validate vouches only for access tokens: a key-management or refresh
// token signature-verifies too, and must not read as a valid session.
func TestValidate_RefusesTokensThatAreNotAccessTokens(t *testing.T) {
	r, key, _ := setupPlatformKeyRouter(t)
	for name, bearer := range map[string]string{
		"key admin": signKeyAdmin(t, key, validKeyAdmin("test-project")),
		"refresh":   signKeyAdmin(t, key, keyAdminToken{projectID: "test-project", audience: "excalibase:test-project", tokenUse: auth.TokenUseRefresh, lifetime: time.Minute}),
	} {
		req := httptest.NewRequest("POST", "/auth/test-org/test-project/validate", strings.NewReader(`{"token":"`+bearer+`"}`))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var resp map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["valid"] != false {
			t.Errorf("%s token validated: %s", name, w.Body.String())
		}
	}
}
