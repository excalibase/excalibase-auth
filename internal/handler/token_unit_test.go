package handler

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestToken_BadJSON(t *testing.T) {
	r := setupUnitRouter(t)
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/token", strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestToken_UnsupportedGrantType(t *testing.T) {
	r := setupUnitRouter(t)
	body := `{"grant_type":"client_credentials"}`
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Errorf("expected 400 for unsupported grant_type, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "grant_type") {
		t.Errorf("error body should mention grant_type, got %q", w.Body.String())
	}
}

func TestToken_MissingGrantType(t *testing.T) {
	r := setupUnitRouter(t)
	body := `{}`
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Errorf("expected 400 for missing grant_type, got %d", w.Code)
	}
}

func TestToken_PasswordGrant_DBUnavailable(t *testing.T) {
	r := setupUnitRouter(t)
	body := `{"grant_type":"password","email":"a@b.com","password":"pass"}`
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	// Pool unreachable → 503 from exchangePassword
	if w.Code != 503 && w.Code != 401 {
		t.Errorf("expected 503 or 401, got %d", w.Code)
	}
}

func TestToken_APIKeyGrant_Missing(t *testing.T) {
	r := setupUnitRouter(t)
	body := `{"grant_type":"api_key"}`
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Errorf("expected 400 for missing api_key, got %d", w.Code)
	}
}

func TestToken_APIKeyGrant_DBUnavailable(t *testing.T) {
	r := setupUnitRouter(t)
	body := `{"grant_type":"api_key","api_key":"esk_pub_live_abcdefghijklmnopqrstuvwx"}`
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 503 && w.Code != 401 {
		t.Errorf("expected 503 or 401, got %d", w.Code)
	}
}

func TestToken_RefreshGrant_DBUnavailable(t *testing.T) {
	r := setupUnitRouter(t)
	body := `{"grant_type":"refresh_token","refresh_token":"some-uuid"}`
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 503 && w.Code != 401 {
		t.Errorf("expected 503 or 401, got %d", w.Code)
	}
}
