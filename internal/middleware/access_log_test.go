package middleware

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccessLogOmitsQueryStringAndEmail(t *testing.T) {
	var out bytes.Buffer
	logger := log.New(&out, "", 0)
	handler := AccessLog(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	req := httptest.NewRequest("GET", "/auth/org/proj-1/verify?email=ann@x.test&token=secret", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	line := out.String()
	for _, leaked := range []string{"?", "ann@x.test", "secret", "token="} {
		if strings.Contains(line, leaked) {
			t.Fatalf("log line leaks %q: %s", leaked, line)
		}
	}
	for _, want := range []string{"GET", "/auth/org/proj-1/verify", "418"} {
		if !strings.Contains(line, want) {
			t.Fatalf("log line missing %q: %s", want, line)
		}
	}
}
