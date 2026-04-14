package handler

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// CRUD endpoints are gated by RequireJWT. Without an Authorization header
// every route must reject with 401 — even before reaching the DB layer.
func TestAPIKey_CreateUnauthenticated(t *testing.T) {
	r := setupUnitRouter(t)
	body := `{"name":"test","keyType":"publishable"}`
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/api-keys/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAPIKey_ListUnauthenticated(t *testing.T) {
	r := setupUnitRouter(t)
	req := httptest.NewRequest("GET", "/auth/test-org/test-project/api-keys/", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAPIKey_RevokeUnauthenticated(t *testing.T) {
	r := setupUnitRouter(t)
	req := httptest.NewRequest("DELETE", "/auth/test-org/test-project/api-keys/42", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAPIKey_CreateBadJSONStillRejectedBeforeJSONDecode(t *testing.T) {
	// JWT middleware fires first, so even malformed JSON without a token
	// should produce 401 rather than 400.
	r := setupUnitRouter(t)
	req := httptest.NewRequest("POST", "/auth/test-org/test-project/api-keys/", strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Errorf("expected 401 (auth before parse), got %d", w.Code)
	}
}
