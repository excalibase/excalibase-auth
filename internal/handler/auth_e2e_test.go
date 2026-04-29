package handler

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/migrate"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

type integrationFixture struct {
	srv     *httptest.Server
	connStr string // direct pgx conn string for tests that need to seed rows
}

func setupIntegration(t *testing.T) (*httptest.Server, func()) {
	fx, cleanup := setupIntegrationFixture(t)
	return fx.srv, cleanup
}

func setupIntegrationFixture(t *testing.T) (*integrationFixture, func()) {
	t.Helper()
	ctx := context.Background()

	// 1. Start real PostgreSQL via testcontainer
	pgContainer, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}

	host, _ := pgContainer.Host(ctx)
	port, _ := pgContainer.MappedPort(ctx, "5432/tcp")
	connStr := fmt.Sprintf(
		"host=%s port=%s user=testuser password=testpass dbname=testdb sslmode=disable",
		host, port.Port(),
	)

	// 2. Mock provisioning vault server
	vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"host": host, "port": port.Port(),
			"database": "testdb", "username": "testuser", "password": "testpass",
		})
	}))

	// 3. Generate test EC key
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}))

	jwtSvc, _ := auth.NewJWTService(privPEM, "excalibase", 3600)

	// 4. Pool manager with auto-migration
	poolMgr := pool.NewManager(vaultServer.URL, "test-pat", 1*time.Hour)
	poolMgr.SetMigrator(func(ctx context.Context, connStr string) error {
		return migrate.Run(connStr)
	})

	// 5. Auth handler + router
	authHandler := NewAuthHandler(poolMgr, jwtSvc, 3600, 604800)
	r := chi.NewRouter()
	r.Route("/auth", authHandler.Routes)
	srv := httptest.NewServer(r)

	cleanup := func() {
		srv.Close()
		vaultServer.Close()
		pgContainer.Terminate(ctx)
	}
	return &integrationFixture{srv: srv, connStr: connStr}, cleanup
}

func postJSON(srv *httptest.Server, path string, body interface{}) *http.Response {
	b, _ := json.Marshal(body)
	resp, _ := http.Post(srv.URL+path, "application/json", bytes.NewReader(b))
	return resp
}

func decodeJSON(resp *http.Response, v interface{}) {
	json.NewDecoder(resp.Body).Decode(v)
	resp.Body.Close()
}

// === INTEGRATION TESTS ===

func TestIntegration_FullAuthFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	srv, cleanup := setupIntegration(t)
	defer cleanup()

	// 1. Register
	resp := postJSON(srv, "/auth/test-org/test-project/register", map[string]string{
		"email": "alice@test.com", "password": "password123", "fullName": "Alice",
	})
	if resp.StatusCode != 201 {
		var body map[string]interface{}
		decodeJSON(resp, &body)
		t.Fatalf("register: got %d, body: %v", resp.StatusCode, body)
	}
	var registerResp map[string]interface{}
	decodeJSON(resp, &registerResp)
	if registerResp["accessToken"] == nil || registerResp["accessToken"] == "" {
		t.Fatal("register should return accessToken")
	}
	if registerResp["refreshToken"] == nil || registerResp["refreshToken"] == "" {
		t.Fatal("register should return refreshToken")
	}

	// 2. Login
	resp = postJSON(srv, "/auth/test-org/test-project/login", map[string]string{
		"email": "alice@test.com", "password": "password123",
	})
	if resp.StatusCode != 200 {
		var body map[string]interface{}
		decodeJSON(resp, &body)
		t.Fatalf("login: got %d, body: %v", resp.StatusCode, body)
	}
	var loginResp map[string]interface{}
	decodeJSON(resp, &loginResp)
	accessToken := loginResp["accessToken"].(string)
	refreshToken := loginResp["refreshToken"].(string)

	// 3. Validate JWT
	resp = postJSON(srv, "/auth/test-org/test-project/validate", map[string]string{
		"token": accessToken,
	})
	var validateResp map[string]interface{}
	decodeJSON(resp, &validateResp)
	if validateResp["valid"] != true {
		t.Fatalf("validate: expected valid=true, got %v", validateResp)
	}
	if validateResp["email"] != "alice@test.com" {
		t.Errorf("email: got %v", validateResp["email"])
	}
	if validateResp["projectId"] != "test-project" {
		t.Errorf("projectId: got %v", validateResp["projectId"])
	}

	// 4. Refresh
	resp = postJSON(srv, "/auth/test-org/test-project/refresh", map[string]string{
		"refreshToken": refreshToken,
	})
	if resp.StatusCode != 200 {
		var body map[string]interface{}
		decodeJSON(resp, &body)
		t.Fatalf("refresh: got %d, body: %v", resp.StatusCode, body)
	}
	var refreshResp map[string]interface{}
	decodeJSON(resp, &refreshResp)
	newRefreshToken := refreshResp["refreshToken"].(string)

	// 5. Old refresh token revoked
	resp = postJSON(srv, "/auth/test-org/test-project/refresh", map[string]string{
		"refreshToken": refreshToken,
	})
	if resp.StatusCode != 401 {
		t.Errorf("old refresh should be revoked, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 6. Logout
	resp = postJSON(srv, "/auth/test-org/test-project/logout", map[string]string{
		"refreshToken": newRefreshToken,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("logout: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 7. Post-logout refresh fails
	resp = postJSON(srv, "/auth/test-org/test-project/refresh", map[string]string{
		"refreshToken": newRefreshToken,
	})
	if resp.StatusCode != 401 {
		t.Errorf("post-logout refresh should fail, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestIntegration_DuplicateRegister(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	srv, cleanup := setupIntegration(t)
	defer cleanup()

	body := map[string]string{
		"email": "dup@test.com", "password": "password123", "fullName": "Dup",
	}
	resp := postJSON(srv, "/auth/test-org/test-project/register", body)
	if resp.StatusCode != 201 {
		t.Fatalf("first register: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = postJSON(srv, "/auth/test-org/test-project/register", body)
	if resp.StatusCode != 409 {
		t.Errorf("duplicate: expected 409, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestIntegration_WrongPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	srv, cleanup := setupIntegration(t)
	defer cleanup()

	postJSON(srv, "/auth/test-org/test-project/register", map[string]string{
		"email": "bob@test.com", "password": "correct123", "fullName": "Bob",
	}).Body.Close()

	resp := postJSON(srv, "/auth/test-org/test-project/login", map[string]string{
		"email": "bob@test.com", "password": "wrong",
	})
	if resp.StatusCode != 401 {
		t.Errorf("wrong password: expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestIntegration_InvalidJWT(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	srv, cleanup := setupIntegration(t)
	defer cleanup()

	resp := postJSON(srv, "/auth/test-org/test-project/validate", map[string]string{
		"token": "invalid.jwt.token",
	})
	var body map[string]interface{}
	decodeJSON(resp, &body)
	if body["valid"] != false {
		t.Errorf("invalid token should return valid=false")
	}
}

// /token with grant_type=password should be functionally equivalent to /login.
func TestIntegration_TokenGrant_Password(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	// register first
	resp := postJSON(srv, "/auth/test-org/test-project/register", map[string]string{
		"email": "carol@test.com", "password": "password123", "fullName": "Carol",
	})
	if resp.StatusCode != 201 {
		t.Fatalf("register: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// /token with grant_type=password
	resp = postJSON(srv, "/auth/test-org/test-project/token", map[string]string{
		"grant_type": "password",
		"email":      "carol@test.com",
		"password":   "password123",
	})
	if resp.StatusCode != 200 {
		var body map[string]interface{}
		decodeJSON(resp, &body)
		t.Fatalf("/token password grant: got %d, body: %v", resp.StatusCode, body)
	}
	var tokenResp map[string]interface{}
	decodeJSON(resp, &tokenResp)
	if tokenResp["accessToken"] == nil || tokenResp["accessToken"] == "" {
		t.Error("/token password grant should return accessToken")
	}
	if tokenResp["refreshToken"] == nil || tokenResp["refreshToken"] == "" {
		t.Error("/token password grant should return refreshToken")
	}
	if tokenResp["tokenType"] != "Bearer" {
		t.Errorf("tokenType: got %v, want Bearer", tokenResp["tokenType"])
	}
}

func TestIntegration_TokenGrant_RefreshToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	// register + capture refresh token
	resp := postJSON(srv, "/auth/test-org/test-project/register", map[string]string{
		"email": "dave@test.com", "password": "password123", "fullName": "Dave",
	})
	var registerResp map[string]interface{}
	decodeJSON(resp, &registerResp)
	rt := registerResp["refreshToken"].(string)

	// /token with grant_type=refresh_token
	resp = postJSON(srv, "/auth/test-org/test-project/token", map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": rt,
	})
	if resp.StatusCode != 200 {
		var body map[string]interface{}
		decodeJSON(resp, &body)
		t.Fatalf("/token refresh grant: got %d, body: %v", resp.StatusCode, body)
	}
	var tokenResp map[string]interface{}
	decodeJSON(resp, &tokenResp)
	if tokenResp["accessToken"] == nil || tokenResp["accessToken"] == "" {
		t.Error("/token refresh grant should return accessToken")
	}

	// old refresh token must be revoked (rotation)
	resp = postJSON(srv, "/auth/test-org/test-project/token", map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": rt,
	})
	if resp.StatusCode != 401 {
		t.Errorf("old refresh token should be revoked, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestIntegration_TokenGrant_UnsupportedReturns400(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	resp := postJSON(srv, "/auth/test-org/test-project/token", map[string]string{
		"grant_type": "client_credentials",
	})
	if resp.StatusCode != 400 {
		t.Errorf("unsupported grant: got %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

// Tighter coverage of the CRUD positive paths: invalid keyType rejection,
// list-shape assertions, revoke idempotency. Complements the happy-path
// journey test below.
func TestIntegration_APIKeyCRUD_InvalidKeyType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	userJWT := registerAndGetJWT(t, srv, "grace@test.com", "Grace")

	body, _ := json.Marshal(map[string]string{"name": "bad", "keyType": "admin"})
	req, _ := http.NewRequest("POST", srv.URL+"/auth/test-org/test-project/api-keys/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+userJWT)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 400 {
		t.Errorf("invalid keyType: got %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestIntegration_APIKeyCRUD_ListShape(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	userJWT := registerAndGetJWT(t, srv, "henry@test.com", "Henry")

	// Create two keys (publishable + secret) so we can verify both types appear.
	for _, kt := range []string{"publishable", "secret"} {
		b, _ := json.Marshal(map[string]string{"name": kt + "-key", "keyType": kt})
		req, _ := http.NewRequest("POST", srv.URL+"/auth/test-org/test-project/api-keys/", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+userJWT)
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != 201 {
			t.Fatalf("create %s: got %d", kt, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// List and verify shape
	req, _ := http.NewRequest("GET", srv.URL+"/auth/test-org/test-project/api-keys/", nil)
	req.Header.Set("Authorization", "Bearer "+userJWT)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("list: got %d", resp.StatusCode)
	}
	var listResp map[string]interface{}
	decodeJSON(resp, &listResp)
	keys := listResp["keys"].([]interface{})
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	// Every key must have id, keyPrefix, keyType, name, createdAt — never plaintext or hash.
	for _, raw := range keys {
		k := raw.(map[string]interface{})
		for _, req := range []string{"id", "keyPrefix", "keyType", "name", "createdAt"} {
			if _, ok := k[req]; !ok {
				t.Errorf("list entry missing required field %q: %v", req, k)
			}
		}
		for _, forbidden := range []string{"plaintext", "keyHash", "key_hash"} {
			if _, ok := k[forbidden]; ok {
				t.Errorf("list entry leaked forbidden field %q", forbidden)
			}
		}
	}
}

func TestIntegration_APIKeyCRUD_RevokeIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	userJWT := registerAndGetJWT(t, srv, "ivy@test.com", "Ivy")

	// Create a key and capture its id
	body, _ := json.Marshal(map[string]string{"name": "idem", "keyType": "publishable"})
	req, _ := http.NewRequest("POST", srv.URL+"/auth/test-org/test-project/api-keys/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+userJWT)
	resp, _ := http.DefaultClient.Do(req)
	var createResp map[string]interface{}
	decodeJSON(resp, &createResp)
	id := int64(createResp["id"].(float64))

	// First DELETE → 204
	req, _ = http.NewRequest("DELETE",
		fmt.Sprintf("%s/auth/test-org/test-project/api-keys/%d", srv.URL, id), nil)
	req.Header.Set("Authorization", "Bearer "+userJWT)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 204 {
		t.Errorf("first revoke: got %d, want 204", resp.StatusCode)
	}
	resp.Body.Close()

	// Second DELETE on the same id → 200 with status=already_revoked_or_missing (idempotent)
	req, _ = http.NewRequest("DELETE",
		fmt.Sprintf("%s/auth/test-org/test-project/api-keys/%d", srv.URL, id), nil)
	req.Header.Set("Authorization", "Bearer "+userJWT)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Errorf("second revoke: got %d, want 200 (idempotent)", resp.StatusCode)
	}
	var idemBody map[string]interface{}
	decodeJSON(resp, &idemBody)
	if idemBody["status"] != "already_revoked_or_missing" {
		t.Errorf("idempotent revoke body: got %v", idemBody)
	}

	// Revoking a non-existent id also returns 200 with the same status
	req, _ = http.NewRequest("DELETE", srv.URL+"/auth/test-org/test-project/api-keys/999999", nil)
	req.Header.Set("Authorization", "Bearer "+userJWT)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Errorf("missing-id revoke: got %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// Bad id (non-numeric) is a 400
	req, _ = http.NewRequest("DELETE", srv.URL+"/auth/test-org/test-project/api-keys/not-a-number", nil)
	req.Header.Set("Authorization", "Bearer "+userJWT)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 400 {
		t.Errorf("bad id: got %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

// registerAndGetJWT is a test helper: registers a new user and returns the
// access token from the register response. Used by tests that need a valid
// user JWT without duplicating the register boilerplate.
func registerAndGetJWT(t *testing.T, srv *httptest.Server, email, name string) string {
	t.Helper()
	resp := postJSON(srv, "/auth/test-org/test-project/register", map[string]string{
		"email": email, "password": "password123", "fullName": name,
	})
	if resp.StatusCode != 201 {
		t.Fatalf("register %s: got %d", email, resp.StatusCode)
	}
	var r map[string]interface{}
	decodeJSON(resp, &r)
	return r["accessToken"].(string)
}

// Full api-key CRUD + grant journey via real HTTP.
// register → login → POST /api-keys → use plaintext via /token → revoke → /token rejects.
func TestIntegration_APIKeyCRUDAndExchange(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	// 1. Register & capture the user JWT.
	resp := postJSON(srv, "/auth/test-org/test-project/register", map[string]string{
		"email": "frank@test.com", "password": "password123", "fullName": "Frank",
	})
	if resp.StatusCode != 201 {
		t.Fatalf("register: got %d", resp.StatusCode)
	}
	var registerResp map[string]interface{}
	decodeJSON(resp, &registerResp)
	userJWT := registerResp["accessToken"].(string)

	// 2. POST /api-keys (authenticated) returns plaintext once.
	createBody, _ := json.Marshal(map[string]string{"name": "ci-key", "keyType": "publishable"})
	req, _ := http.NewRequest("POST", srv.URL+"/auth/test-org/test-project/api-keys/", bytes.NewReader(createBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+userJWT)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 201 {
		var body map[string]interface{}
		decodeJSON(resp, &body)
		t.Fatalf("create api key: got %d, body: %v", resp.StatusCode, body)
	}
	var createResp map[string]interface{}
	decodeJSON(resp, &createResp)
	plaintext, _ := createResp["plaintext"].(string)
	if plaintext == "" || !strings.HasPrefix(plaintext, "esk_pub_live_") {
		t.Fatalf("unexpected plaintext: %q", plaintext)
	}
	apiKeyID := int64(createResp["id"].(float64))

	// 3. GET /api-keys lists the new key but never the hash or plaintext.
	req, _ = http.NewRequest("GET", srv.URL+"/auth/test-org/test-project/api-keys/", nil)
	req.Header.Set("Authorization", "Bearer "+userJWT)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("list api keys: got %d", resp.StatusCode)
	}
	var listResp map[string]interface{}
	decodeJSON(resp, &listResp)
	keys := listResp["keys"].([]interface{})
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	first := keys[0].(map[string]interface{})
	if _, present := first["plaintext"]; present {
		t.Error("list response must not include plaintext")
	}
	if _, present := first["keyHash"]; present {
		t.Error("list response must not include keyHash")
	}

	// 4. Exchange the plaintext via /token.
	resp = postJSON(srv, "/auth/test-org/test-project/token", map[string]string{
		"grant_type": "api_key",
		"api_key":    plaintext,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("/token api_key after CRUD create: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 5. DELETE /api-keys/{id} revokes via the HTTP path.
	req, _ = http.NewRequest("DELETE",
		fmt.Sprintf("%s/auth/test-org/test-project/api-keys/%d", srv.URL, apiKeyID), nil)
	req.Header.Set("Authorization", "Bearer "+userJWT)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 204 {
		t.Errorf("revoke: got %d, want 204", resp.StatusCode)
	}
	resp.Body.Close()

	// 6. Post-revocation /token must reject.
	resp = postJSON(srv, "/auth/test-org/test-project/token", map[string]string{
		"grant_type": "api_key",
		"api_key":    plaintext,
	})
	if resp.StatusCode != 401 {
		t.Errorf("post-revocation: got %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

// Full api-key grant flow with direct DB seeding (kept for the JWT-shape
// assertions). Verifies the issued JWT carries scope and the apikey:<id> sub.
func TestIntegration_TokenGrant_APIKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupIntegrationFixture(t)
	defer cleanup()
	srv := fx.srv

	// 1. Register a user — also primes the pool manager so the migration runs
	//    against the test DB before we try to INSERT into auth.api_keys.
	resp := postJSON(srv, "/auth/test-org/test-project/register", map[string]string{
		"email": "eve@test.com", "password": "password123", "fullName": "Eve",
	})
	if resp.StatusCode != 201 {
		t.Fatalf("register: got %d", resp.StatusCode)
	}
	var registerResp map[string]interface{}
	decodeJSON(resp, &registerResp)
	userID := int64(registerResp["user"].(map[string]interface{})["id"].(float64))

	// 2. Generate an api key and insert it directly into the project DB. This
	//    bypasses the (Phase 3) CRUD handler but exercises the grant_type=api_key
	//    path end-to-end, including the JWT shape.
	plaintext, hash, prefix, err := service.GenerateAPIKey(service.KeyTypePublishable)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	dbPool, err := pgxpool.New(context.Background(), fx.connStr)
	if err != nil {
		t.Fatalf("connect direct: %v", err)
	}
	defer dbPool.Close()

	_, err = dbPool.Exec(context.Background(),
		`INSERT INTO auth.api_keys (key_hash, key_prefix, key_type, name, created_by)
		 VALUES ($1, $2, 'publishable', 'test-key', $3)`,
		hash, prefix, userID,
	)
	if err != nil {
		t.Fatalf("insert api_key: %v", err)
	}

	// 3. Exchange the plaintext via /token.
	resp = postJSON(srv, "/auth/test-org/test-project/token", map[string]string{
		"grant_type": "api_key",
		"api_key":    plaintext,
	})
	if resp.StatusCode != 200 {
		var body map[string]interface{}
		decodeJSON(resp, &body)
		t.Fatalf("/token api_key grant: got %d, body: %v", resp.StatusCode, body)
	}
	var tokenResp map[string]interface{}
	decodeJSON(resp, &tokenResp)
	accessToken, _ := tokenResp["accessToken"].(string)
	if accessToken == "" {
		t.Fatal("/token api_key grant should return accessToken")
	}
	// api_key flow does NOT issue a refresh token.
	if rt, _ := tokenResp["refreshToken"].(string); rt != "" {
		t.Errorf("api_key grant must not issue refreshToken, got %q", rt)
	}

	// 4. Validate the JWT shape: scope=public, sub=apikey:<id>.
	resp = postJSON(srv, "/auth/test-org/test-project/validate", map[string]string{
		"token": accessToken,
	})
	var validateResp map[string]interface{}
	decodeJSON(resp, &validateResp)
	if validateResp["valid"] != true {
		t.Fatalf("api_key JWT should validate: %v", validateResp)
	}
	// validateResp["email"] is sourced from the JWT's "sub" claim, which we set
	// to "apikey:<keyID>" for api-key tokens.
	if sub, _ := validateResp["email"].(string); !strings.HasPrefix(sub, "apikey:") {
		t.Errorf("expected sub to start with 'apikey:', got %q", sub)
	}

	// 5. Revoking the key (set revoked_at) makes future exchanges fail.
	_, err = dbPool.Exec(context.Background(),
		`UPDATE auth.api_keys SET revoked_at = NOW() WHERE key_hash = $1`, hash,
	)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	resp = postJSON(srv, "/auth/test-org/test-project/token", map[string]string{
		"grant_type": "api_key",
		"api_key":    plaintext,
	})
	if resp.StatusCode != 401 {
		t.Errorf("revoked api key should fail with 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

