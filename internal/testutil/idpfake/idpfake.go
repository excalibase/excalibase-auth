// Package idpfake is an in-process Google (OpenID Connect) and GitHub for
// sign-in tests: authorize, code exchange with PKCE, signed id_tokens with a
// JWKS, and GitHub's user and email reads. Ported from provisioning's Studio
// sign-in fake (EXC-13); a separate Go module, so the code is copied.
package idpfake

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	ClientID     = "fake-client-id"
	ClientSecret = "fake-client-secret"
	keyID        = "fake-key-1"
)

// User is the account the next authorize request signs in as.
type User struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// Tamper makes the next id_token wrong in one way, to prove it is refused.
type Tamper int

const (
	TamperNone Tamper = iota
	TamperNonce
	TamperAudience
	TamperSignature
	TamperIssuer
)

type grant struct {
	user        User
	challenge   string
	redirectURI string
	nonce       string
	provider    string
}

// IdP is the fake. Its methods are safe for concurrent use.
type IdP struct {
	Server *httptest.Server

	key      *rsa.PrivateKey
	rogue    *rsa.PrivateKey
	mu       sync.Mutex
	next     User
	tamper   Tamper
	codes    map[string]grant
	tokens   map[string]User
	requests []url.Values
}

// New starts a fake that closes with the test.
func New(t testing.TB) *IdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	rogue, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	fake := &IdP{key: key, rogue: rogue, codes: map[string]grant{}, tokens: map[string]User{}}
	fake.Server = httptest.NewServer(fake.routes())
	t.Cleanup(fake.Server.Close)
	return fake
}

func (f *IdP) URL() string { return f.Server.URL }

// GoogleIssuer is the iss of the fake's id_tokens.
func (f *IdP) GoogleIssuer() string { return f.Server.URL + "/google" }

// SignInAs sets who the next authorize request signs in.
func (f *IdP) SignInAs(user User) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next = user
}

// TamperNext breaks the next id_token.
func (f *IdP) TamperNext(tamper Tamper) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tamper = tamper
}

// AuthorizeRequests is every authorize query received, oldest first.
func (f *IdP) AuthorizeRequests() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]url.Values(nil), f.requests...)
}

func (f *IdP) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /google/authorize", f.authorize("google"))
	mux.HandleFunc("POST /google/token", f.exchange)
	mux.HandleFunc("GET /google/certs", f.certs)
	mux.HandleFunc("GET /github/login/oauth/authorize", f.authorize("github"))
	mux.HandleFunc("POST /github/login/oauth/access_token", f.exchange)
	mux.HandleFunc("GET /github/api/user", f.githubUser)
	mux.HandleFunc("GET /github/api/user/emails", f.githubEmails)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func randomString() string {
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// authorize signs the configured user in at once and sends the browser back.
func (f *IdP) authorize(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		f.mu.Lock()
		f.requests = append(f.requests, query)
		user := f.next
		f.mu.Unlock()
		if query.Get("client_id") != ClientID || query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		code := randomString()
		f.mu.Lock()
		f.codes[code] = grant{user: user, challenge: query.Get("code_challenge"), redirectURI: query.Get("redirect_uri"), nonce: query.Get("nonce"), provider: provider}
		f.mu.Unlock()
		target, _ := url.Parse(query.Get("redirect_uri"))
		back := target.Query()
		back.Set("code", code)
		back.Set("state", query.Get("state"))
		target.RawQuery = back.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
	}
}

func clientCredentials(r *http.Request) (string, string) {
	if id, secret, ok := r.BasicAuth(); ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
		return id, secret
	}
	return r.Form.Get("client_id"), r.Form.Get("client_secret")
}

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (f *IdP) exchange(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if id, secret := clientCredentials(r); id != ClientID || secret != ClientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	f.mu.Lock()
	issued, ok := f.codes[r.Form.Get("code")]
	delete(f.codes, r.Form.Get("code"))
	f.mu.Unlock()
	if !ok || issued.redirectURI != r.Form.Get("redirect_uri") || challengeOf(r.Form.Get("code_verifier")) != issued.challenge {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	access := "fake-access-" + randomString()
	f.mu.Lock()
	f.tokens[access] = issued.user
	f.mu.Unlock()
	body := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 3600}
	if issued.provider == "google" {
		body["id_token"] = f.idToken(issued)
	}
	writeJSON(w, http.StatusOK, body)
}

func (f *IdP) idToken(issued grant) string {
	f.mu.Lock()
	tamper := f.tamper
	f.tamper = TamperNone
	f.mu.Unlock()
	claims := jwt.MapClaims{
		"iss": f.GoogleIssuer(), "aud": ClientID, "sub": issued.user.Subject, "nonce": issued.nonce,
		"email": issued.user.Email, "email_verified": issued.user.EmailVerified, "name": issued.user.Name,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}
	signer := f.key
	switch tamper {
	case TamperNonce:
		claims["nonce"] = "not-the-nonce"
	case TamperAudience:
		claims["aud"] = "someone-else"
	case TamperIssuer:
		claims["iss"] = "https://evil.example"
	case TamperSignature:
		signer = f.rogue
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	signed, err := token.SignedString(signer)
	if err != nil {
		panic(fmt.Sprintf("sign id_token: %v", err))
	}
	return signed
}

func (f *IdP) certs(w http.ResponseWriter, _ *http.Request) {
	public := f.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "alg": "RS256", "use": "sig", "kid": keyID,
		"n": base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
	}}})
}

func (f *IdP) bearerUser(r *http.Request) (User, bool) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return User{}, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	user, ok := f.tokens[raw]
	return user, ok
}

func (f *IdP) githubUser(w http.ResponseWriter, r *http.Request) {
	user, ok := f.bearerUser(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "Bad credentials"})
		return
	}
	var id int64
	_, _ = fmt.Sscan(user.Subject, &id)
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "login": "octo-" + user.Subject, "name": user.Name})
}

func (f *IdP) githubEmails(w http.ResponseWriter, r *http.Request) {
	user, ok := f.bearerUser(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "Bad credentials"})
		return
	}
	writeJSON(w, http.StatusOK, []map[string]any{
		{"email": "secondary-" + user.Email, "primary": false, "verified": true},
		{"email": user.Email, "primary": true, "verified": user.EmailVerified},
	})
}
