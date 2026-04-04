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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/migrate"
	"github.com/excalibase/auth/internal/pool"
	"github.com/go-chi/chi/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupIntegration(t *testing.T) (*httptest.Server, func()) {
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
	authHandler := NewAuthHandler(poolMgr, jwtSvc, 604800)
	r := chi.NewRouter()
	r.Route("/auth", authHandler.Routes)
	srv := httptest.NewServer(r)

	cleanup := func() {
		srv.Close()
		vaultServer.Close()
		pgContainer.Terminate(ctx)
	}
	return srv, cleanup
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
	resp := postJSON(srv, "/auth/test-project/register", map[string]string{
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
	resp = postJSON(srv, "/auth/test-project/login", map[string]string{
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
	resp = postJSON(srv, "/auth/test-project/validate", map[string]string{
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
	resp = postJSON(srv, "/auth/test-project/refresh", map[string]string{
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
	resp = postJSON(srv, "/auth/test-project/refresh", map[string]string{
		"refreshToken": refreshToken,
	})
	if resp.StatusCode != 401 {
		t.Errorf("old refresh should be revoked, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 6. Logout
	resp = postJSON(srv, "/auth/test-project/logout", map[string]string{
		"refreshToken": newRefreshToken,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("logout: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 7. Post-logout refresh fails
	resp = postJSON(srv, "/auth/test-project/refresh", map[string]string{
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
	resp := postJSON(srv, "/auth/test-project/register", body)
	if resp.StatusCode != 201 {
		t.Fatalf("first register: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = postJSON(srv, "/auth/test-project/register", body)
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

	postJSON(srv, "/auth/test-project/register", map[string]string{
		"email": "bob@test.com", "password": "correct123", "fullName": "Bob",
	}).Body.Close()

	resp := postJSON(srv, "/auth/test-project/login", map[string]string{
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

	resp := postJSON(srv, "/auth/test-project/validate", map[string]string{
		"token": "invalid.jwt.token",
	})
	var body map[string]interface{}
	decodeJSON(resp, &body)
	if body["valid"] != false {
		t.Errorf("invalid token should return valid=false")
	}
}

