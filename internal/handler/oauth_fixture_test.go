package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/migrate"
	"github.com/excalibase/auth/internal/oauth"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/testmysql"
	"github.com/excalibase/auth/internal/testutil/idpfake"
	"github.com/excalibase/auth/internal/token"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	oauthProject  = "/auth/test-org/test-project"
	appCallback   = "https://app.test/auth/callback"
	oauthPassword = "password123"
)

// signInSettings is what the fake control plane answers on /info; tests change it.
type signInSettings struct {
	mu            sync.Mutex
	providers     []string
	redirectURLs  []string
	allowNewUsers bool
	emailOTP      bool
	userAPI       bool
	infoDown      bool
	secretMissing bool
}

func (s *signInSettings) set(change func(*signInSettings)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	change(s)
}

// oauthFixture is auth for test-project, its database, a fake Google/GitHub
// and a fake control plane with the project's sign-in settings.
type oauthFixture struct {
	*integrationFixture
	idp      *idpfake.IdP
	settings *signInSettings
	// passwordIsNull reads users.password straight from the database.
	passwordIsNull func(t *testing.T, email string) bool
	// count reads a table's row count straight from the database.
	count func(t *testing.T, table string) int
	// disable switches an account off straight in the database.
	disable func(t *testing.T, email string)
}

func (s *signInSettings) info(authURL string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	providers := []map[string]string{}
	for _, name := range s.providers {
		providers = append(providers, map[string]string{
			"provider": name, "clientId": idpfake.ClientID,
			"callbackUrl": authURL + oauthProject + "/callback/" + name,
		})
	}
	return map[string]any{
		"projectId": "test-project", "orgSlug": "test-org", "siteUrl": "https://app.test",
		"redirectUrls": s.redirectURLs, "allowNewUsers": s.allowNewUsers, "oauthProviders": providers,
		"emailOtpEnabled": s.emailOTP, "userApiEnabled": s.userAPI,
	}
}

func (s *signInSettings) provisioning(record any, authURL *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		s.mu.Lock()
		down, missing := s.infoDown, s.secretMissing
		s.mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/info"):
			if down {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(s.info(*authURL))
		case strings.Contains(r.URL.Path, "/auth/providers/"):
			if missing {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"client_secret": idpfake.ClientSecret})
		default:
			_ = json.NewEncoder(w).Encode(record)
		}
	})
}

func newOAuthFixture(t *testing.T, record any, configure func(*pool.Manager), tune ...func(*AuthHandler)) *oauthFixture {
	t.Helper()
	settings := &signInSettings{providers: []string{"google", "github"}, redirectURLs: []string{appCallback}, allowNewUsers: true, emailOTP: true, userAPI: true}
	var authURL string
	provisioning := httptest.NewServer(settings.provisioning(record, &authURL))
	t.Cleanup(provisioning.Close)

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(priv)
	jwtSvc, err := auth.NewJWTService(string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), "excalibase", 3600)
	if err != nil {
		t.Fatal(err)
	}
	mgr := pool.NewManager(provisioning.URL, token.Literal("test-pat"), time.Hour)
	mgr.SetSSLMode("disable")
	configure(mgr)

	idp := idpfake.New(t)
	h := NewAuthHandler(mgr, jwtSvc, 604800).WithOAuthProviders(map[string]oauth.Provider{
		"google": oauth.Google(oauth.FakeGoogleEndpoints(idp.URL())),
		"github": oauth.GitHub(oauth.FakeGitHubEndpoints(idp.URL())),
	}, http.DefaultClient)
	// Every sign-in step reads the settings afresh, so a test sees its own change.
	h.signInMaxAge = 0
	for _, apply := range tune {
		apply(h)
	}
	r := chi.NewRouter()
	r.Route("/auth", h.Routes)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	authURL = srv.URL
	return &oauthFixture{integrationFixture: &integrationFixture{srv: srv, signingKey: priv, jwtSvc: jwtSvc}, idp: idp, settings: settings}
}

func newPostgresOAuthFixture(t *testing.T, tune ...func(*AuthHandler)) *oauthFixture {
	t.Helper()
	ctx := context.Background()
	container, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("testdb"), postgres.WithUsername("testuser"), postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(30*time.Second)))
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })
	host, _ := container.Host(ctx)
	port, _ := container.MappedPort(ctx, "5432/tcp")
	record := map[string]string{"host": host, "port": port.Port(), "database": "testdb", "username": "testuser", "password": "testpass"}
	fx := newOAuthFixture(t, record, func(mgr *pool.Manager) { mgr.SetMigrator(migrate.Run) }, tune...)
	direct, err := pgxpool.New(ctx, fmt.Sprintf("postgres://testuser:testpass@%s:%s/testdb?sslmode=disable", host, port.Port()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(direct.Close)
	fx.passwordIsNull = func(t *testing.T, email string) bool {
		var null bool
		if err := direct.QueryRow(ctx, "SELECT password IS NULL FROM auth.users WHERE email = $1", email).Scan(&null); err != nil {
			t.Fatalf("read password of %s: %v", email, err)
		}
		return null
	}
	fx.disable = func(t *testing.T, email string) {
		if _, err := direct.Exec(ctx, "UPDATE auth.users SET enabled = false WHERE email = $1", email); err != nil {
			t.Fatalf("disable %s: %v", email, err)
		}
	}
	fx.count = func(t *testing.T, table string) int {
		var n int
		if err := direct.QueryRow(ctx, "SELECT count(*) FROM auth."+table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		return n
	}
	return fx
}

func newMySQLOAuthFixture(t *testing.T, tune ...func(*AuthHandler)) *oauthFixture {
	t.Helper()
	server := testmysql.Start(t)
	record := server.ProvisionAuth(t, "auth-admin-pw")
	fx := newOAuthFixture(t, record, func(mgr *pool.Manager) {
		mgr.SetMigrator(migrate.Run)
		mgr.SetMySQLMigrator(migrate.RunMySQL)
	}, tune...)
	root := server.Root(t)
	fx.passwordIsNull = func(t *testing.T, email string) bool {
		var null bool
		if err := root.QueryRow("SELECT password IS NULL FROM `auth`.`users` WHERE email = ?", email).Scan(&null); err != nil {
			t.Fatalf("read password of %s: %v", email, err)
		}
		return null
	}
	fx.disable = func(t *testing.T, email string) {
		if _, err := root.Exec("UPDATE `auth`.`users` SET enabled = FALSE WHERE email = ?", email); err != nil {
			t.Fatalf("disable %s: %v", email, err)
		}
	}
	fx.count = func(t *testing.T, table string) int {
		var n int
		if err := root.QueryRow("SELECT count(*) FROM `auth`.`" + table + "`").Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		return n
	}
	return fx
}

// newBrowser is a browser that keeps cookies and stops at every redirect.
func newBrowser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

var browser = newBrowser()

func get(t *testing.T, raw string) *http.Response {
	t.Helper()
	return getWith(t, browser, raw)
}

func getWith(t *testing.T, client *http.Client, raw string) *http.Response {
	t.Helper()
	resp, err := client.Get(raw)
	if err != nil {
		t.Fatalf("GET %s: %v", raw, err)
	}
	return resp
}

// authorizeURL is what the SDK sends the browser to.
func (fx *oauthFixture) authorizeURL(provider, redirectTo, challenge string) string {
	query := url.Values{"provider": {provider}, "redirect_to": {redirectTo}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	return fx.srv.URL + oauthProject + "/authorize?" + query.Encode()
}

// browserSignIn walks authorize -> provider -> callback and returns where the
// browser lands back in the app, plus the verifier the SDK kept.
func (fx *oauthFixture) browserSignIn(t *testing.T, provider string, user idpfake.User) (*url.URL, string) {
	t.Helper()
	fx.idp.SignInAs(user)
	flow, _ := oauth.NewFlow()
	resp := get(t, fx.authorizeURL(provider, appCallback, oauth.S256(flow.Verifier)))
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: %d", resp.StatusCode)
	}
	atProvider := get(t, resp.Header.Get("Location"))
	atProvider.Body.Close()
	callback := get(t, atProvider.Header.Get("Location"))
	callback.Body.Close()
	if callback.StatusCode != http.StatusFound {
		t.Fatalf("callback: %d", callback.StatusCode)
	}
	landed, err := url.Parse(callback.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return landed, flow.Verifier
}

func (fx *oauthFixture) exchange(code, verifier string) (*http.Response, map[string]any) {
	resp := postJSON(fx.srv, oauthProject+"/token", map[string]string{"grant_type": "pkce", "auth_code": code, "code_verifier": verifier})
	var body map[string]any
	decodeJSON(resp, &body)
	return resp, body
}

// signIn is a whole provider sign-in that must succeed.
func (fx *oauthFixture) signIn(t *testing.T, provider string, user idpfake.User) map[string]any {
	t.Helper()
	landed, verifier := fx.browserSignIn(t, provider, user)
	if landed.Query().Get("error") != "" {
		t.Fatalf("sign-in landed with error %q", landed.Query().Get("error"))
	}
	resp, body := fx.exchange(landed.Query().Get("code"), verifier)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange: %d %v", resp.StatusCode, body)
	}
	return body
}

func userIDOf(body map[string]any) float64 {
	user, _ := body["user"].(map[string]any)
	id, _ := user["id"].(float64)
	return id
}
