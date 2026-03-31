//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

func post(t *testing.T, path string, body interface{}) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(authServerURL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func decode(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	return body
}

func assertStatus(t *testing.T, resp *http.Response, expected int) {
	t.Helper()
	if resp.StatusCode != expected {
		body := decode(t, resp)
		t.Fatalf("expected %d, got %d: %v", expected, resp.StatusCode, body)
	}
}
