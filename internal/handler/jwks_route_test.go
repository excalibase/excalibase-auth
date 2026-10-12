package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/excalibase/auth/internal/auth"
)

// A customer backend verifies end-user tokens offline: the public keys are
// served under the public /auth prefix the edge already routes (EXC-600).
func TestJWKSIsServedUnderThePublicAuthPrefix(t *testing.T) {
	r := forgotPasswordRouter(t, nil)
	for _, path := range []string{
		"/auth/.well-known/jwks.json",
		"/auth/acme/proj-a/.well-known/jwks.json",
	} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Fatalf("%s: content type %q", path, ct)
		}
		if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age") {
			t.Fatalf("%s: cache control %q", path, cc)
		}
		var set auth.JWKS
		if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil || len(set.Keys) != 1 {
			t.Fatalf("%s: body %s (%v)", path, rec.Body, err)
		}
		key := set.Keys[0]
		if key.Kty != "EC" || key.Alg != "ES256" || key.X == "" || key.Y == "" {
			t.Fatalf("%s: key %+v", path, key)
		}
		// Public keys only: an EC private key would carry d.
		if strings.Contains(rec.Body.String(), `"d"`) {
			t.Fatalf("%s: the set carries private key material: %s", path, rec.Body)
		}
	}
}
