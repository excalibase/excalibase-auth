package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/excalibase/auth/internal/service"
)

func jwtPayload(t *testing.T, tok string) map[string]interface{} {
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
	return claims
}

// tokenResponse decodes a 200 token response and returns its body.
func tokenResponse(t *testing.T, resp *http.Response, what string) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	decodeJSON(resp, &body)
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		t.Fatalf("%s: got %d, body %v", what, resp.StatusCode, body)
	}
	return body
}

func assertRoleClaims(t *testing.T, tok, wantRole, wantScope string, wantUserID bool) {
	t.Helper()
	claims := jwtPayload(t, tok)
	if claims["role"] != wantRole {
		t.Errorf("role: got %v, want %s", claims["role"], wantRole)
	}
	allowed, _ := claims["allowed_roles"].([]interface{})
	if len(allowed) != 1 || allowed[0] != wantRole {
		t.Errorf("allowed_roles: got %v, want [%s]", claims["allowed_roles"], wantRole)
	}
	if claims["scope"] != wantScope {
		t.Errorf("scope: got %v, want %s", claims["scope"], wantScope)
	}
	if _, present := claims["userId"]; present != wantUserID {
		t.Errorf("userId present=%v, want %v (claims %v)", present, wantUserID, claims)
	}
}

func assertRefusedForRole(t *testing.T, resp *http.Response, what string) {
	t.Helper()
	var body map[string]interface{}
	decodeJSON(resp, &body)
	if resp.StatusCode != 403 || body["error"] != "invalid_account_role" {
		t.Errorf("%s: got %d %v, want 403 invalid_account_role", what, resp.StatusCode, body)
	}
}

func setAccountRole(t *testing.T, fx *integrationFixture, email, role string) {
	t.Helper()
	if _, err := directDB(t, fx).Exec(context.Background(),
		"UPDATE auth.users SET role = $1 WHERE email = $2", role, email); err != nil {
		t.Fatalf("set role: %v", err)
	}
}

func TestIntegration_RoleClaims_PasswordTokensCarryAccountRole(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupIntegrationFixture(t)
	defer cleanup()

	registered := tokenResponse(t, postJSON(fx.srv, "/auth/test-org/test-project/register", map[string]string{
		"email": "role@test.com", "password": "password123", "fullName": "Role",
	}), "register")
	assertRoleClaims(t, registered["accessToken"].(string), "user", "authenticated", true)

	setAccountRole(t, fx, "role@test.com", "editor")
	loggedIn := tokenResponse(t, postJSON(fx.srv, "/auth/test-org/test-project/login", map[string]string{
		"email": "role@test.com", "password": "password123",
	}), "login")
	assertRoleClaims(t, loggedIn["accessToken"].(string), "editor", "authenticated", true)

	setAccountRole(t, fx, "role@test.com", "manager")
	refreshed := tokenResponse(t, refreshWith(fx.srv, loggedIn["refreshToken"].(string)), "refresh")
	assertRoleClaims(t, refreshed["accessToken"].(string), "manager", "authenticated", true)
}

func TestIntegration_RoleClaims_ReservedOrInvalidAccountRoleRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupIntegrationFixture(t)
	defer cleanup()
	refreshToken := registerForRefreshToken(t, fx.srv, "bad@test.com")

	for _, role := range []string{"service", "anon", "Not-A-Role"} {
		setAccountRole(t, fx, "bad@test.com", role)
		assertRefusedForRole(t, postJSON(fx.srv, "/auth/test-org/test-project/login", map[string]string{
			"email": "bad@test.com", "password": "password123",
		}), "login as "+role)
		assertRefusedForRole(t, postJSON(fx.srv, "/auth/test-org/test-project/token", map[string]string{
			"grant_type": "password", "email": "bad@test.com", "password": "password123",
		}), "password grant as "+role)
		assertRefusedForRole(t, refreshWith(fx.srv, refreshToken), "refresh as "+role)
	}

	setAccountRole(t, fx, "bad@test.com", "user")
	restored := tokenResponse(t, refreshWith(fx.srv, refreshToken), "refresh after the role is fixed")
	assertRoleClaims(t, restored["accessToken"].(string), "user", "authenticated", true)
}

func TestIntegration_RoleClaims_APIKeyTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupIntegrationFixture(t)
	defer cleanup()

	registered := tokenResponse(t, postJSON(fx.srv, "/auth/test-org/test-project/register", map[string]string{
		"email": "owner@test.com", "password": "password123", "fullName": "Owner",
	}), "register")
	ownerID := int64(registered["user"].(map[string]interface{})["id"].(float64))

	ownedPublishable, _ := seedAPIKey(t, fx, service.KeyTypePublishable, &ownerID)
	publishable := tokenResponse(t, exchangeAPIKeyForTest(fx.srv, ownedPublishable), "publishable exchange")
	assertRoleClaims(t, publishable["accessToken"].(string), "anon", "public", false)

	secretKey, _ := seedAPIKey(t, fx, service.KeyTypeSecret, nil)
	secret := tokenResponse(t, exchangeAPIKeyForTest(fx.srv, secretKey), "secret exchange")
	assertRoleClaims(t, secret["accessToken"].(string), "service", "service", false)

	var validated map[string]interface{}
	decodeJSON(postJSON(fx.srv, "/auth/test-org/test-project/validate", map[string]string{
		"token": publishable["accessToken"].(string),
	}), &validated)
	if validated["valid"] != true || validated["role"] != "anon" {
		t.Errorf("validate publishable: %v", validated)
	}
	if _, present := validated["userId"]; present {
		t.Errorf("validate must not report a userId for an api-key token: %v", validated)
	}
}
