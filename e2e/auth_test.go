//go:build e2e

package e2e

import (
	"testing"
)

func TestE2E_RegisterAndLogin(t *testing.T) {
	// Register
	resp := post(t, "/auth/test-org/my-app/register", map[string]string{
		"email": "alice@example.com", "password": "SecureP@ss123", "fullName": "Alice",
	})
	assertStatus(t, resp, 201)
	body := decode(t, resp)

	if body["accessToken"] == nil || body["accessToken"] == "" {
		t.Fatal("expected accessToken")
	}
	if body["refreshToken"] == nil || body["refreshToken"] == "" {
		t.Fatal("expected refreshToken")
	}
	if body["tokenType"] != "Bearer" {
		t.Errorf("tokenType: got %v", body["tokenType"])
	}
	user := body["user"].(map[string]interface{})
	if user["email"] != "alice@example.com" {
		t.Errorf("email: got %v", user["email"])
	}

	// Login with same credentials
	resp = post(t, "/auth/test-org/my-app/login", map[string]string{
		"email": "alice@example.com", "password": "SecureP@ss123",
	})
	assertStatus(t, resp, 200)
	loginBody := decode(t, resp)
	if loginBody["accessToken"] == nil || loginBody["accessToken"] == "" {
		t.Fatal("login should return accessToken")
	}
}

func TestE2E_ValidateJWT(t *testing.T) {
	// Register + login to get a token
	post(t, "/auth/test-org/my-app/register", map[string]string{
		"email": "validate@example.com", "password": "Pass1234", "fullName": "Val",
	}).Body.Close()

	resp := post(t, "/auth/test-org/my-app/login", map[string]string{
		"email": "validate@example.com", "password": "Pass1234",
	})
	loginBody := decode(t, resp)
	token := loginBody["accessToken"].(string)

	// Validate
	resp = post(t, "/auth/test-org/my-app/validate", map[string]string{"token": token})
	assertStatus(t, resp, 200)
	body := decode(t, resp)

	if body["valid"] != true {
		t.Fatalf("expected valid=true, got %v", body)
	}
	if body["email"] != "validate@example.com" {
		t.Errorf("email: got %v", body["email"])
	}
	if body["projectId"] != "test-org/my-app" {
		t.Errorf("projectId: got %v", body["projectId"])
	}
	if body["role"] != "user" {
		t.Errorf("role: got %v", body["role"])
	}
}

func TestE2E_RefreshToken(t *testing.T) {
	post(t, "/auth/test-org/my-app/register", map[string]string{
		"email": "refresh@example.com", "password": "Pass1234", "fullName": "Ref",
	}).Body.Close()

	resp := post(t, "/auth/test-org/my-app/login", map[string]string{
		"email": "refresh@example.com", "password": "Pass1234",
	})
	loginBody := decode(t, resp)
	refreshToken := loginBody["refreshToken"].(string)
	oldAccess := loginBody["accessToken"].(string)

	// Refresh
	resp = post(t, "/auth/test-org/my-app/refresh", map[string]string{"refreshToken": refreshToken})
	assertStatus(t, resp, 200)
	body := decode(t, resp)
	newAccess := body["accessToken"].(string)

	if newAccess == oldAccess {
		t.Error("refresh should return a different accessToken")
	}

	// Old refresh token should be revoked
	resp = post(t, "/auth/test-org/my-app/refresh", map[string]string{"refreshToken": refreshToken})
	assertStatus(t, resp, 401)
	resp.Body.Close()
}

func TestE2E_Logout(t *testing.T) {
	post(t, "/auth/test-org/my-app/register", map[string]string{
		"email": "logout@example.com", "password": "Pass1234", "fullName": "Log",
	}).Body.Close()

	resp := post(t, "/auth/test-org/my-app/login", map[string]string{
		"email": "logout@example.com", "password": "Pass1234",
	})
	body := decode(t, resp)
	refreshToken := body["refreshToken"].(string)

	// Logout
	resp = post(t, "/auth/test-org/my-app/logout", map[string]string{"refreshToken": refreshToken})
	assertStatus(t, resp, 200)
	resp.Body.Close()

	// Refresh after logout should fail
	resp = post(t, "/auth/test-org/my-app/refresh", map[string]string{"refreshToken": refreshToken})
	assertStatus(t, resp, 401)
	resp.Body.Close()
}

func TestE2E_DuplicateRegister(t *testing.T) {
	body := map[string]string{
		"email": "dup@example.com", "password": "Pass1234", "fullName": "Dup",
	}

	resp := post(t, "/auth/test-org/my-app/register", body)
	assertStatus(t, resp, 201)
	resp.Body.Close()

	resp = post(t, "/auth/test-org/my-app/register", body)
	assertStatus(t, resp, 409)
	resp.Body.Close()
}

func TestE2E_WrongPassword(t *testing.T) {
	post(t, "/auth/test-org/my-app/register", map[string]string{
		"email": "wrong@example.com", "password": "Correct123", "fullName": "Wrong",
	}).Body.Close()

	resp := post(t, "/auth/test-org/my-app/login", map[string]string{
		"email": "wrong@example.com", "password": "BadPassword",
	})
	assertStatus(t, resp, 401)
	resp.Body.Close()
}

func TestE2E_InvalidJWT(t *testing.T) {
	resp := post(t, "/auth/test-org/my-app/validate", map[string]string{"token": "not.a.jwt"})
	assertStatus(t, resp, 200)
	body := decode(t, resp)
	if body["valid"] != false {
		t.Error("invalid JWT should return valid=false")
	}
}
