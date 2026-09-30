package handler

import (
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/middleware"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/ratelimit"
	"github.com/excalibase/auth/internal/token"
)

const (
	usersPath    = "/auth/test-org/test-project/users"
	userRolePath = "/auth/test-org/test-project/users/5/role"
)

// userAdminToken is what the control plane signs to manage end-user roles.
type userAdminToken struct {
	projectID string
	audience  string
	tokenUse  string
	actor     string
	lifetime  time.Duration
}

func validUserAdmin(projectID string) userAdminToken {
	return userAdminToken{
		projectID: projectID, audience: auth.KeyAdminAudience(projectID),
		tokenUse: auth.TokenUseUserAdmin, actor: "plat-user-9", lifetime: time.Minute,
	}
}

func signUserAdmin(t *testing.T, key *ecdsa.PrivateKey, spec userAdminToken) string {
	t.Helper()
	now := time.Now()
	mapClaims := jwt.MapClaims{
		"iss": "excalibase", "sub": "svc-provisioning", "projectId": spec.projectID,
		"aud": []string{spec.audience}, "token_use": spec.tokenUse,
		"iat": now.Unix(), "exp": now.Add(spec.lifetime).Unix(),
	}
	if spec.actor != "" {
		mapClaims["actor"] = spec.actor
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodES256, mapClaims).SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// mintServiceToken signs what a secret-key grant yields.
func mintServiceToken(t *testing.T, svc *auth.JWTService, projectID string, keyID int64) string {
	t.Helper()
	signed, err := svc.Sign(auth.Claims{
		Sub: "apikey:3", ProjectID: projectID, Role: auth.RoleService,
		AllowedRoles: []string{auth.RoleService}, Scope: "service", KeyID: keyID,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return signed
}

func mintScopedToken(t *testing.T, svc *auth.JWTService, role, scope string) string {
	t.Helper()
	signed, err := svc.Sign(auth.Claims{Sub: "x", UserID: 7, ProjectID: "test-project", Role: role, Scope: scope, KeyID: 3})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return signed
}

var userRoutes = []struct{ method, path, body string }{
	{http.MethodGet, usersPath, ""},
	{http.MethodPut, userRolePath, `{"role":"editor","allowedRoles":["editor","user"]}`},
}

func callUserRoute(r http.Handler, method, path, bearer, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal %q: %v", w.Body.String(), err)
	}
	code, _ := out["error"].(string)
	return code
}

// Past authorization the request reaches the unreachable project database: 503.
func TestUsers_AcceptedCallersPassAuthorization(t *testing.T) {
	r, key, svc := setupPlatformKeyRouter(t)
	callers := map[string]string{
		"user admin":         signUserAdmin(t, key, validUserAdmin("test-project")),
		"secret-key service": mintServiceToken(t, svc, "test-project", 3),
	}
	for name, bearer := range callers {
		for _, route := range userRoutes {
			if w := callUserRoute(r, route.method, route.path, bearer, route.body); w.Code != 503 {
				t.Errorf("%s: %s %s got %d %s, want 503", name, route.method, route.path, w.Code, w.Body)
			}
		}
	}
}

func TestUsers_RefusedCallers(t *testing.T) {
	r, key, svc := setupPlatformKeyRouter(t)
	long := validUserAdmin("test-project")
	long.lifetime = 2 * time.Minute
	noActor := validUserAdmin("test-project")
	noActor.actor = ""
	blankActor := validUserAdmin("test-project")
	blankActor.actor = "  "
	engineAud := validUserAdmin("test-project")
	engineAud.audience = "excalibase:test-project"
	otherAud := validUserAdmin("test-project")
	otherAud.audience = auth.KeyAdminAudience("other-project")
	refused := map[string]string{
		"key admin":                 signKeyAdmin(t, key, validKeyAdmin("test-project")),
		"end user":                  mintToken(t, svc, "test-project", "authenticated"),
		"publishable key (anon)":    mintScopedToken(t, svc, auth.RoleAnon, "public"),
		"service scope, user role":  mintScopedToken(t, svc, "user", "service"),
		"service role, public":      mintScopedToken(t, svc, auth.RoleService, "public"),
		"service without key id":    mintServiceToken(t, svc, "test-project", 0),
		"user admin, other project": signUserAdmin(t, key, validUserAdmin("other-project")),
		"service, other project":    mintServiceToken(t, svc, "other-project", 3),
		"user admin over 60 s":      signUserAdmin(t, key, long),
		"user admin without actor":  signUserAdmin(t, key, noActor),
		"user admin, blank actor":   signUserAdmin(t, key, blankActor),
		"user admin, engine aud":    signUserAdmin(t, key, engineAud),
		"user admin, other aud":     signUserAdmin(t, key, otherAud),
		"refresh token_use":         signKeyAdmin(t, key, keyAdminToken{projectID: "test-project", audience: "excalibase:test-project", tokenUse: auth.TokenUseRefresh, lifetime: time.Minute}),
	}
	for name, bearer := range refused {
		for _, route := range userRoutes {
			w := callUserRoute(r, route.method, route.path, bearer, route.body)
			if w.Code != 403 {
				t.Errorf("%s: %s %s got %d, want 403", name, route.method, route.path, w.Code)
				continue
			}
			if code := errorCode(t, w); code != "token_project_mismatch" && code != "insufficient_scope" {
				t.Errorf("%s: error %q is not a stable code", name, code)
			}
		}
	}
}

func TestUsers_OtherProjectAnswersProjectMismatch(t *testing.T) {
	r, key, _ := setupPlatformKeyRouter(t)
	w := callUserRoute(r, http.MethodGet, usersPath, "", "")
	if w.Code != 401 {
		t.Errorf("no token: got %d, want 401", w.Code)
	}
	w = callUserRoute(r, http.MethodGet, usersPath, "not-a-jwt", "")
	if w.Code != 401 {
		t.Errorf("garbage token: got %d, want 401", w.Code)
	}
	w = callUserRoute(r, http.MethodGet, usersPath, signUserAdmin(t, key, validUserAdmin("other-project")), "")
	if w.Code != 403 || errorCode(t, w) != "token_project_mismatch" {
		t.Errorf("other project: got %d %s", w.Code, w.Body)
	}
}

// Least privilege: the user-admin token never reaches api keys.
func TestAPIKey_UserAdminTokenIsRefused(t *testing.T) {
	r, key, _ := setupPlatformKeyRouter(t)
	for i, code := range callKeyRoutes(t, r, signUserAdmin(t, key, validUserAdmin("test-project"))) {
		if code != 403 {
			t.Errorf("%s %s: got %d, want 403", keyRoutes[i].method, keyRoutes[i].path, code)
		}
	}
}

func TestUsers_SetRoleRefusesInvalidRequests(t *testing.T) {
	r, key, _ := setupPlatformKeyRouter(t)
	bearer := signUserAdmin(t, key, validUserAdmin("test-project"))
	tooMany := make([]string, 0, auth.MaxAllowedRoles+1)
	for i := 0; i <= auth.MaxAllowedRoles; i++ {
		tooMany = append(tooMany, `"r`+strings.Repeat("x", i)+`"`)
	}
	cases := []struct{ name, path, body, want string }{
		{"not json", userRolePath, `{`, "invalid_request"},
		{"unknown field", userRolePath, `{"role":"editor","admin":true}`, "invalid_request"},
		{"missing role", userRolePath, `{}`, "invalid_role"},
		{"malformed role", userRolePath, `{"role":"Editor"}`, "invalid_role"},
		{"anon", userRolePath, `{"role":"anon"}`, "reserved_role"},
		{"service", userRolePath, `{"role":"service"}`, "reserved_role"},
		{"platform role", userRolePath, `{"role":"postgres"}`, "reserved_role"},
		{"pg_ prefix", userRolePath, `{"role":"pg_read_all_data"}`, "reserved_role"},
		{"excalibase_ prefix", userRolePath, `{"role":"excalibase_x"}`, "reserved_role"},
		{"reserved allowed entry", userRolePath, `{"role":"editor","allowedRoles":["editor","app"]}`, "reserved_role"},
		{"role not allowed", userRolePath, `{"role":"editor","allowedRoles":["user"]}`, "role_not_in_allowed_roles"},
		{"too many allowed", userRolePath, `{"role":"r","allowedRoles":[` + strings.Join(tooMany, ",") + `]}`, "too_many_allowed_roles"},
		{"bad user id", "/auth/test-org/test-project/users/abc/role", `{"role":"editor"}`, "invalid_user_id"},
		{"zero user id", "/auth/test-org/test-project/users/0/role", `{"role":"editor"}`, "invalid_user_id"},
	}
	for _, tc := range cases {
		w := callUserRoute(r, http.MethodPut, tc.path, bearer, tc.body)
		if w.Code != 400 || errorCode(t, w) != tc.want {
			t.Errorf("%s: got %d %s, want 400 %s", tc.name, w.Code, w.Body, tc.want)
		}
	}
}

func TestUsers_ListRefusesInvalidPagination(t *testing.T) {
	r, key, _ := setupPlatformKeyRouter(t)
	bearer := signUserAdmin(t, key, validUserAdmin("test-project"))
	for _, query := range []string{"?limit=0", "?limit=501", "?limit=abc", "?offset=-1", "?offset=x"} {
		w := callUserRoute(r, http.MethodGet, usersPath+query, bearer, "")
		if w.Code != 400 || errorCode(t, w) != "invalid_pagination" {
			t.Errorf("%s: got %d %s, want 400 invalid_pagination", query, w.Code, w.Body)
		}
	}
	for _, query := range []string{"", "?limit=500", "?limit=1&offset=10"} {
		if w := callUserRoute(r, http.MethodGet, usersPath+query, bearer, ""); w.Code != 503 {
			t.Errorf("%s: got %d, want 503 (valid pagination)", query, w.Code)
		}
	}
}

func TestParsePagination_Defaults(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, usersPath, nil)
	limit, offset, err := parsePagination(req)
	if err != nil || limit != 100 || offset != 0 {
		t.Errorf("defaults: got %d %d %v, want 100 0", limit, offset, err)
	}
}

// Role changes share the token route's per-IP budget.
func TestUsers_SetRoleIsRateLimited(t *testing.T) {
	r, key := setupRateLimitedUserRouter(t)
	bearer := signUserAdmin(t, key, validUserAdmin("test-project"))
	for i := 0; i < 2; i++ {
		if w := callUserRoute(r, http.MethodPut, userRolePath, bearer, `{"role":"editor"}`); w.Code != 503 {
			t.Fatalf("call %d: got %d, want 503", i+1, w.Code)
		}
	}
	if w := callUserRoute(r, http.MethodPut, userRolePath, bearer, `{"role":"editor"}`); w.Code != http.StatusTooManyRequests {
		t.Errorf("third call: got %d, want 429", w.Code)
	}
}

func setupRateLimitedUserRouter(t *testing.T) (chi.Router, *ecdsa.PrivateKey) {
	t.Helper()
	_, key, svc := setupPlatformKeyRouter(t)
	clock := &manualClock{now: time.Unix(1_700_000_000, 0)}
	limits := middleware.NewRateLimits(middleware.RateLimitConfig{
		Window: time.Minute, RegisterPerIP: 2, LoginPerIP: 2, TokenPerIP: 2,
		RegisterPerProject: 100, LoginFailures: 100, FailureWindow: 15 * time.Minute,
	}, ratelimit.WithClock(clock.Now))
	mgr := pool.NewManager("http://127.0.0.1:1", token.Literal("fake-pat"), time.Hour)
	r := chi.NewRouter()
	r.Route("/auth", NewAuthHandler(mgr, svc, 604800).WithRateLimits(limits).Routes)
	return r, key
}
