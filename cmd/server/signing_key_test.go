package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fixedToken string

func (t fixedToken) Get() (string, error) { return string(t), nil }

// A sealed vault (manual unseal, EXC-579) is a wait, not a crash: auth stays
// unready and says why until an admin unseals it.
func TestWaitForSigningKey_WaitsWhileTheVaultIsSealed(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer svc" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if calls < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"vault is sealed"}`))
			return
		}
		_, _ = w.Write([]byte(`{"key":"PEM"}`))
	}))
	defer server.Close()

	var logged []string
	key, err := waitForSigningKey(server.URL, fixedToken("svc"), func(time.Duration) {},
		func(format string, args ...interface{}) { logged = append(logged, format) })
	if err != nil {
		t.Fatalf("waitForSigningKey: %v", err)
	}
	if key != "PEM" || calls != 3 {
		t.Fatalf("key=%q calls=%d", key, calls)
	}
	if len(logged) == 0 || !strings.Contains(logged[0], "sealed") {
		t.Fatalf("logged %v, want the sealed vault named", logged)
	}
}

func TestWaitForSigningKey_OtherFailuresStillStopTheStart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	if _, err := waitForSigningKey(server.URL, fixedToken("svc"), func(time.Duration) {},
		func(string, ...interface{}) {}); err == nil {
		t.Fatal("a 403 must stop the start")
	}
}
