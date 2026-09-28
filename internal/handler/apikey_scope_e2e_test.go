package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/excalibase/auth/internal/migrate"
	"github.com/excalibase/auth/internal/service"
	"github.com/jackc/pgx/v5/pgxpool"
)

const apiKeysPath = "/auth/test-org/test-project/api-keys/"

// seedAPIKey inserts a key straight into the project DB, the way an operator
// provisions one outside the end-user plane. A nil owner means no end user.
func seedAPIKey(t *testing.T, fx *integrationFixture, keyType service.KeyType, owner *int64) (string, int64) {
	t.Helper()
	migrationPool, err := pgxpool.New(context.Background(), fx.connStr+" search_path=auth")
	if err != nil {
		t.Fatalf("connect for migrations: %v", err)
	}
	defer migrationPool.Close()
	if err := migrate.Run(context.Background(), migrationPool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	plaintext, hash, prefix, err := service.GenerateAPIKey(keyType)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	db, err := pgxpool.New(context.Background(), fx.connStr)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer db.Close()
	var id int64
	if err := db.QueryRow(context.Background(),
		`INSERT INTO auth.api_keys (key_hash, key_prefix, key_type, name, created_by)
		 VALUES ($1, $2, $3, 'seeded', $4) RETURNING id`,
		hash, prefix, string(keyType), owner,
	).Scan(&id); err != nil {
		t.Fatalf("insert api key: %v", err)
	}
	return plaintext, id
}

func exchangeAPIKeyForTest(srv *httptest.Server, plaintext string) *http.Response {
	return postJSON(srv, "/auth/test-org/test-project/token", map[string]string{
		"grant_type": "api_key", "api_key": plaintext,
	})
}

// operatorJWT returns a service-scope token from an operator-provisioned secret key.
func operatorJWT(t *testing.T, fx *integrationFixture) string {
	t.Helper()
	plaintext, _ := seedAPIKey(t, fx, service.KeyTypeSecret, nil)
	resp := exchangeAPIKeyForTest(fx.srv, plaintext)
	if resp.StatusCode != 200 {
		t.Fatalf("operator key exchange: got %d", resp.StatusCode)
	}
	var out map[string]interface{}
	decodeJSON(resp, &out)
	tok, _ := out["accessToken"].(string)
	if scope := jwtScope(t, tok); scope != "service" {
		t.Fatalf("operator token scope: got %q, want service", scope)
	}
	return tok
}

func jwtScope(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	scope, _ := claims["scope"].(string)
	return scope
}

func sendAuthed(t *testing.T, srv *httptest.Server, method, path, bearer string, body interface{}) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, srv.URL+path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

func expectStatus(t *testing.T, resp *http.Response, want int, what string) {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != want {
		t.Errorf("%s: got %d, want %d", what, resp.StatusCode, want)
	}
}

func TestIntegration_APIKey_EndUserRefusedAtEveryStep(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupIntegrationFixture(t)
	defer cleanup()

	userJWT := registerAndGetJWT(t, fx.srv, "mallory@test.com", "Mallory")
	operatorKey, operatorKeyID := seedAPIKey(t, fx, service.KeyTypeSecret, nil)

	for _, kt := range []string{"secret", "publishable"} {
		resp := sendAuthed(t, fx.srv, "POST", apiKeysPath, userJWT, map[string]string{"name": "x", "keyType": kt})
		expectStatus(t, resp, 403, "end user creating a "+kt+" key")
	}
	expectStatus(t, sendAuthed(t, fx.srv, "GET", apiKeysPath, userJWT, nil), 403, "end user listing keys")
	expectStatus(t, sendAuthed(t, fx.srv, "DELETE", fmt.Sprintf("%s%d", apiKeysPath, operatorKeyID), userJWT, nil),
		403, "end user revoking the operator's key")

	expectStatus(t, exchangeAPIKeyForTest(fx.srv, operatorKey), 200, "operator key after the end user's revoke attempt")
}

// A secret key owned by an end user (left over from before end users were cut
// off) must not be exchangeable for a service token.
func TestIntegration_APIKey_UserOwnedSecretKeyYieldsNoServiceToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupIntegrationFixture(t)
	defer cleanup()

	resp := postJSON(fx.srv, "/auth/test-org/test-project/register", map[string]string{
		"email": "oscar@test.com", "password": "password123", "fullName": "Oscar",
	})
	var reg map[string]interface{}
	decodeJSON(resp, &reg)
	userID := int64(reg["user"].(map[string]interface{})["id"].(float64))

	plaintext, _ := seedAPIKey(t, fx, service.KeyTypeSecret, &userID)
	expectStatus(t, exchangeAPIKeyForTest(fx.srv, plaintext), 401, "user-owned secret key exchange")
}

func TestIntegration_APIKey_OperatorManagesKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupIntegrationFixture(t)
	defer cleanup()
	opJWT := operatorJWT(t, fx)

	resp := sendAuthed(t, fx.srv, "POST", apiKeysPath, opJWT, map[string]string{"name": "backend", "keyType": "secret"})
	if resp.StatusCode != 201 {
		t.Fatalf("operator create secret key: got %d", resp.StatusCode)
	}
	var created map[string]interface{}
	decodeJSON(resp, &created)
	newKey, _ := created["plaintext"].(string)
	newID := int64(created["id"].(float64))

	resp = exchangeAPIKeyForTest(fx.srv, newKey)
	if resp.StatusCode != 200 {
		t.Fatalf("operator-created secret key exchange: got %d", resp.StatusCode)
	}
	var tokenResp map[string]interface{}
	decodeJSON(resp, &tokenResp)
	if scope := jwtScope(t, tokenResp["accessToken"].(string)); scope != "service" {
		t.Errorf("operator-created secret key scope: got %q, want service", scope)
	}

	expectStatus(t, sendAuthed(t, fx.srv, "GET", apiKeysPath, opJWT, nil), 200, "operator list")
	expectStatus(t, sendAuthed(t, fx.srv, "DELETE", fmt.Sprintf("%s%d", apiKeysPath, newID), opJWT, nil), 204, "operator revoke")
	expectStatus(t, exchangeAPIKeyForTest(fx.srv, newKey), 401, "revoked key exchange")
}
