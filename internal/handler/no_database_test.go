package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/token"
	"github.com/go-chi/chi/v5"
)

// EXC-426: end-user auth for a project created without a database is refused
// with 409 "project has no database" — the project's state, not an outage.
func TestEndUserAuthRefusesAProjectWithoutADatabase(t *testing.T) {
	provisioning := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"project has no database"}`))
	}))
	defer provisioning.Close()

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(priv)
	jwtSvc, _ := auth.NewJWTService(string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), "excalibase", 3600)
	h := NewAuthHandler(pool.NewManager(provisioning.URL, token.Literal("pat"), time.Hour), jwtSvc, 604800)
	r := chi.NewRouter()
	r.Route("/auth", h.Routes)

	for _, tc := range []struct{ path, body string }{
		{"/auth/org/apps-only/register", `{"email":"a@b.co","password":"Str0ng!Passw0rd","fullName":"A"}`},
		{"/auth/org/apps-only/login", `{"email":"a@b.co","password":"Str0ng!Passw0rd"}`},
		{"/auth/org/apps-only/token", `{"grant_type":"password","email":"a@b.co","password":"Str0ng!Passw0rd"}`},
	} {
		req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "project has no database") {
			t.Errorf("%s: got %d %s, want 409 project has no database", tc.path, w.Code, w.Body.String())
		}
	}
}
