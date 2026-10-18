package handler

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/migrate"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/testmysql"
	"github.com/excalibase/auth/internal/token"
	"github.com/go-chi/chi/v5"
)

const mysqlProject = "/auth/test-org/test-project"

// setupMySQLFixture serves test-project from a MySQL project's auth database,
// reached through the record provisioning files for it (ADR 0041, EXC-626).
func setupMySQLFixture(t *testing.T, requireVerification bool) (*integrationFixture, *stubSender) {
	t.Helper()
	server := testmysql.Start(t)
	record := server.ProvisionAuth(t, "auth-admin-pw")
	provisioning := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/info") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"projectId": "test-project", "orgSlug": "test-org",
				"requireEmailVerification": requireVerification, "siteUrl": "https://site.test",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(record)
	}))
	t.Cleanup(provisioning.Close)

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(priv)
	jwtSvc, err := auth.NewJWTService(string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), "excalibase", 3600)
	if err != nil {
		t.Fatal(err)
	}
	mgr := pool.NewManager(provisioning.URL, token.Literal("test-pat"), time.Hour)
	mgr.SetSSLMode("disable") // the Postgres setting of the docker AIO; MySQL stays on TLS
	mgr.SetMigrator(migrate.Run)
	mgr.SetMySQLMigrator(migrate.RunMySQL)
	sender := &stubSender{}
	h := NewAuthHandler(mgr, jwtSvc, 604800)
	h.SetEmail(sender, "")
	r := chi.NewRouter()
	r.Route("/auth", h.Routes)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return &integrationFixture{srv: srv, signingKey: priv, jwtSvc: jwtSvc}, sender
}

func send(t *testing.T, fx *integrationFixture, method, path, bearer string, body any) (*http.Response, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, fx.srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	var out map[string]any
	decodeJSON(resp, &out)
	return resp, out
}

func TestIntegration_MySQLProjectEndUsers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, _ := setupMySQLFixture(t, false)
	t.Run("SignUpAndSignInCarryTheProjectAndUser", func(t *testing.T) { mysqlSignUpAndSignIn(t, fx) })
	t.Run("RefreshRotatesAndAReplayEndsTheSession", func(t *testing.T) { mysqlRefresh(t, fx) })
	t.Run("LogoutEndsTheSession", func(t *testing.T) { mysqlLogout(t, fx) })
	t.Run("RoleChangeAppliesFromTheNextSignIn", func(t *testing.T) { mysqlRoleChange(t, fx) })
	t.Run("APIKeysSignInAsAnonAndRevoke", func(t *testing.T) { mysqlAPIKeys(t, fx) })
}

func mysqlSignUpAndSignIn(t *testing.T, fx *integrationFixture) {
	registered := tokenResponse(t, postJSON(fx.srv, mysqlProject+"/register", map[string]string{
		"email": "alice@mysql.test", "password": "password123", "fullName": "Alice",
	}), "register")
	userID := registered["user"].(map[string]any)["id"].(float64)
	claims := jwtPayload(t, registered["accessToken"].(string))
	if claims["projectId"] != "test-project" || claims["userId"] != userID || claims["role"] != "user" ||
		claims["scope"] != "authenticated" || claims["sub"] != "alice@mysql.test" {
		t.Fatalf("claims = %v", claims)
	}

	if resp := postJSON(fx.srv, mysqlProject+"/register", map[string]string{
		"email": "alice@mysql.test", "password": "password123", "fullName": "Again",
	}); resp.StatusCode != http.StatusConflict {
		t.Fatalf("taken address: got %d, want 409", resp.StatusCode)
	}
	if resp := postJSON(fx.srv, mysqlProject+"/register", map[string]string{
		"email": "ALICE@mysql.test", "password": "password123", "fullName": "Upper",
	}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("differently cased address (a new account, as on Postgres): got %d", resp.StatusCode)
	}

	if resp := postJSON(fx.srv, mysqlProject+"/login", map[string]string{
		"email": "alice@mysql.test", "password": "wrong-password",
	}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d", resp.StatusCode)
	}
	loggedIn := tokenResponse(t, postJSON(fx.srv, mysqlProject+"/login", map[string]string{
		"email": "alice@mysql.test", "password": "password123",
	}), "login")
	if jwtPayload(t, loggedIn["accessToken"].(string))["userId"] != userID {
		t.Fatal("login token names another user")
	}
	_, valid := send(t, fx, http.MethodPost, mysqlProject+"/validate", "", map[string]string{"token": loggedIn["accessToken"].(string)})
	if valid["valid"] != true || valid["userId"] != userID {
		t.Fatalf("validate = %v", valid)
	}
	_, other := send(t, fx, http.MethodPost, "/auth/test-org/other-project/validate", "", map[string]string{"token": loggedIn["accessToken"].(string)})
	if other["valid"] != false {
		t.Fatalf("token validated for another project: %v", other)
	}
}

func mysqlRefresh(t *testing.T, fx *integrationFixture) {
	first := registerForRefreshToken(t, fx.srv, "bob@mysql.test")
	rotated := tokenResponse(t, refreshWith(fx.srv, first), "refresh")
	successor := rotated["refreshToken"].(string)
	if successor == "" || successor == first {
		t.Fatalf("refresh issued %q", successor)
	}
	if jwtPayload(t, rotated["accessToken"].(string))["sub"] != "bob@mysql.test" {
		t.Fatal("refreshed token names another user")
	}
	if resp := refreshWith(fx.srv, first); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed token: got %d", resp.StatusCode)
	}
	if resp := refreshWith(fx.srv, successor); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a replay must end the whole session; successor got %d", resp.StatusCode)
	}
	legacy := postJSON(fx.srv, mysqlProject+"/refresh", map[string]string{"refreshToken": loginForRefreshToken(t, fx.srv, "bob@mysql.test")})
	if legacy.StatusCode != http.StatusOK {
		t.Fatalf("legacy /refresh: got %d", legacy.StatusCode)
	}
	legacy.Body.Close()
}

func mysqlLogout(t *testing.T, fx *integrationFixture) {
	session := registerForRefreshToken(t, fx.srv, "carol@mysql.test")
	if resp, body := send(t, fx, http.MethodPost, mysqlProject+"/logout", "", map[string]string{"refreshToken": session}); resp.StatusCode != http.StatusOK {
		t.Fatalf("logout: %d %v", resp.StatusCode, body)
	}
	if resp := refreshWith(fx.srv, session); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refresh after logout: got %d", resp.StatusCode)
	}
}

func mysqlRoleChange(t *testing.T, fx *integrationFixture) {
	session := registerForRefreshToken(t, fx.srv, "dan@mysql.test")
	admin := signUserAdmin(t, fx.signingKey, validUserAdmin("test-project"))
	resp, listing := send(t, fx, http.MethodGet, mysqlProject+"/users/?limit=500", admin, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list users: %d %v", resp.StatusCode, listing)
	}
	var danID int64
	for _, raw := range listing["users"].([]any) {
		user := raw.(map[string]any)
		if user["email"] == "dan@mysql.test" {
			danID = int64(user["id"].(float64))
		}
	}
	if danID == 0 {
		t.Fatalf("dan not listed: %v", listing)
	}
	resp, changed := send(t, fx, http.MethodPut, rolePath(danID), admin,
		map[string]any{"role": "editor", "allowedRoles": []string{"editor", "user"}})
	if resp.StatusCode != http.StatusOK || changed["role"] != "editor" {
		t.Fatalf("set role: %d %v", resp.StatusCode, changed)
	}
	if resp := refreshWith(fx.srv, session); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session survived the role change: %d", resp.StatusCode)
	}
	loggedIn := tokenResponse(t, postJSON(fx.srv, mysqlProject+"/login", map[string]string{
		"email": "dan@mysql.test", "password": "password123",
	}), "login after role change")
	claims := jwtPayload(t, loggedIn["accessToken"].(string))
	if claims["role"] != "editor" || strings.Join(stringList(claims["allowed_roles"]), ",") != "editor,user" {
		t.Fatalf("claims = %v", claims)
	}
}

func mysqlAPIKeys(t *testing.T, fx *integrationFixture) {
	keyAdmin := signKeyAdmin(t, fx.signingKey, validKeyAdmin("test-project"))
	resp, created := send(t, fx, http.MethodPost, mysqlProject+"/api-keys/", keyAdmin,
		map[string]string{"name": "web", "keyType": "publishable"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create key: %d %v", resp.StatusCode, created)
	}
	exchanged := tokenResponse(t, postJSON(fx.srv, mysqlProject+"/token", map[string]string{
		"grant_type": "api_key", "api_key": created["plaintext"].(string),
	}), "api key exchange")
	if claims := jwtPayload(t, exchanged["accessToken"].(string)); claims["role"] != auth.RoleAnon || claims["projectId"] != "test-project" {
		t.Fatalf("api key claims = %v", claims)
	}
	_, listed := send(t, fx, http.MethodGet, mysqlProject+"/api-keys/", keyAdmin, nil)
	keys := listed["keys"].([]any)
	if len(keys) != 1 || keys[0].(map[string]any)["lastUsedAt"] == nil {
		t.Fatalf("listing = %v", listed)
	}
	id := int64(created["id"].(float64))
	if resp, _ := send(t, fx, http.MethodDelete, mysqlProject+"/api-keys/"+itoa(id), keyAdmin, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if resp := postJSON(fx.srv, mysqlProject+"/token", map[string]string{
		"grant_type": "api_key", "api_key": created["plaintext"].(string),
	}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked key exchanged: %d", resp.StatusCode)
	}
}

func TestIntegration_MySQLProjectVerificationAndReset(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, sender := setupMySQLFixture(t, true)
	if resp := postJSON(fx.srv, mysqlProject+"/register", map[string]string{
		"email": "erin@mysql.test", "password": "password123", "fullName": "Erin",
	}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", resp.StatusCode)
	}
	if resp := postJSON(fx.srv, mysqlProject+"/login", map[string]string{
		"email": "erin@mysql.test", "password": "password123",
	}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unverified login: got %d, want 403", resp.StatusCode)
	}
	verify := verificationLinkToken(t, sender.last(t))
	if resp, body := send(t, fx, http.MethodPost, mysqlProject+"/verify-email", "", map[string]string{"token": verify}); resp.StatusCode != http.StatusOK || body["verified"] != true || body["passwordResetRequired"] != nil {
		t.Fatalf("verify: %d %v", resp.StatusCode, body)
	}
	if resp, _ := send(t, fx, http.MethodPost, mysqlProject+"/verify-email", "", map[string]string{"token": verify}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a link is single use: got %d", resp.StatusCode)
	}
	session := loginForRefreshToken(t, fx.srv, "erin@mysql.test")

	sender.reset()
	if resp, _ := send(t, fx, http.MethodPost, mysqlProject+"/forgot-password", "", map[string]string{"email": "erin@mysql.test"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("forgot: %d", resp.StatusCode)
	}
	reset := resetLinkToken(t, sender.last(t))
	if resp, body := send(t, fx, http.MethodPost, mysqlProject+"/reset-password", "", map[string]string{"token": reset, "newPassword": "new-password-456"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("reset: %d %v", resp.StatusCode, body)
	}
	if resp := refreshWith(fx.srv, session); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session survived the reset: %d", resp.StatusCode)
	}
	if resp := postJSON(fx.srv, mysqlProject+"/login", map[string]string{"email": "erin@mysql.test", "password": "password123"}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old password: %d", resp.StatusCode)
	}
	if resp := postJSON(fx.srv, mysqlProject+"/login", map[string]string{"email": "erin@mysql.test", "password": "new-password-456"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("new password: %d", resp.StatusCode)
	}
	if resp, _ := send(t, fx, http.MethodPost, mysqlProject+"/reset-password", "", map[string]string{"token": reset, "newPassword": "another-pass-789"}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("reset link reused: %d", resp.StatusCode)
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
