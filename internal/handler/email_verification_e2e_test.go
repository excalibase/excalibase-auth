package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/email"
	"github.com/excalibase/auth/internal/migrate"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/token"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	testOrgProject = "/auth/test-org/test-project"
	aliceEmail     = "alice@verify.test"
	alicePassword  = "password123"
)

// stubSender records outgoing mail instead of delivering it.
type stubSender struct {
	mu       sync.Mutex
	messages []email.Message
	failNext bool
}

func (s *stubSender) Send(_ context.Context, msg email.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNext {
		s.failNext = false
		return fmt.Errorf("stub delivery failure")
	}
	s.messages = append(s.messages, msg)
	return nil
}

func (s *stubSender) all() []email.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]email.Message(nil), s.messages...)
}

func (s *stubSender) last(t *testing.T) email.Message {
	t.Helper()
	msgs := s.all()
	if len(msgs) == 0 {
		t.Fatal("expected an email to have been sent")
	}
	return msgs[len(msgs)-1]
}

func (s *stubSender) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = nil
}

// claimsOf decodes a JWT payload without verifying it — the tests assert on
// claim content, not on signatures.
func claimsOf(t *testing.T, jwtString string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(jwtString, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwtString)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims
}

type verifyFixture struct {
	srv    *httptest.Server
	sender *stubSender
	db     *pgxpool.Pool
}

// setupVerifyFixture boots Postgres plus a provisioning stub whose /info
// response carries the project's verification setting.
func setupVerifyFixture(t *testing.T, requireVerification bool) (*verifyFixture, func()) {
	t.Helper()
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}

	host, _ := pgContainer.Host(ctx)
	port, _ := pgContainer.MappedPort(ctx, "5432/tcp")
	connStr := fmt.Sprintf("host=%s port=%s user=testuser password=testpass dbname=testdb sslmode=disable",
		host, port.Port())

	provisioning := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/info") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"projectId":                "test-project",
				"projectName":              "Test Project",
				"orgSlug":                  "test-org",
				"requireEmailVerification": requireVerification,
				"siteUrl":                  "https://site.test",
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"host": host, "port": port.Port(),
			"database": "testdb", "username": "testuser", "password": "testpass",
		})
	}))

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}))
	jwtSvc, _ := auth.NewJWTService(privPEM, "excalibase", 3600)

	poolMgr := pool.NewManager(provisioning.URL, token.Literal("test-pat"), time.Hour)
	poolMgr.SetMigrator(func(ctx context.Context, connStr string) error { return migrate.Run(connStr) })

	sender := &stubSender{}
	h := NewAuthHandler(poolMgr, jwtSvc, 3600, 604800)
	h.SetEmail(sender, "https://fallback.test")

	r := chi.NewRouter()
	r.Route("/auth", h.Routes)
	srv := httptest.NewServer(r)

	db, err := pgxpool.New(ctx, connStr+" search_path=auth")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	cleanup := func() {
		db.Close()
		srv.Close()
		provisioning.Close()
		pgContainer.Terminate(ctx)
	}
	return &verifyFixture{srv: srv, sender: sender, db: db}, cleanup
}

func (f *verifyFixture) register(t *testing.T, userEmail string) *http.Response {
	t.Helper()
	return postJSON(f.srv, testOrgProject+"/register", map[string]string{
		"email": userEmail, "password": alicePassword, "fullName": "Alice",
	})
}

// verificationLinkToken pulls the token out of the URL in the captured email.
func verificationLinkToken(t *testing.T, msg email.Message) string {
	t.Helper()
	link := msg.Data["verifyUrl"]
	_, raw, found := strings.Cut(link, "token=")
	if !found {
		t.Fatalf("verify url has no token query parameter: %q", link)
	}
	return raw
}

func (f *verifyFixture) emailVerified(t *testing.T, userEmail string) bool {
	t.Helper()
	var verified bool
	err := f.db.QueryRow(context.Background(),
		"SELECT email_verified FROM auth.users WHERE email = $1", userEmail).Scan(&verified)
	if err != nil {
		t.Fatalf("read email_verified: %v", err)
	}
	return verified
}

// === registration sends a verification email, stored hashed ===

func TestIntegration_RegisterStoresTokenHashedAndEmailsTheLink(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()

	resp := fx.register(t, aliceEmail)
	if resp.StatusCode != 201 {
		t.Fatalf("register: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	if fx.emailVerified(t, aliceEmail) {
		t.Fatal("a freshly registered account must start unverified")
	}

	msg := fx.sender.last(t)
	if msg.Template != email.TemplateVerifyEmail {
		t.Errorf("template: got %q", msg.Template)
	}
	if msg.To != aliceEmail {
		t.Errorf("recipient: got %q", msg.To)
	}
	plaintext := verificationLinkToken(t, msg)

	// The link must be built from the project's own site URL, not the fallback.
	if !strings.HasPrefix(msg.Data["verifyUrl"], "https://site.test/verify?token=") {
		t.Errorf("verify url: got %q", msg.Data["verifyUrl"])
	}

	// Only the hash may be persisted.
	var stored string
	err := fx.db.QueryRow(context.Background(),
		"SELECT token_hash FROM auth.email_verification_tokens").Scan(&stored)
	if err != nil {
		t.Fatalf("read token row: %v", err)
	}
	if stored == plaintext {
		t.Fatal("the raw token must never be stored")
	}
	if stored != token.Hash(plaintext) {
		t.Fatal("stored value must be the SHA-256 hash of the emailed token")
	}
}

func TestIntegration_VerifyEmailMarksAccountVerified(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()

	fx.register(t, aliceEmail).Body.Close()
	plaintext := verificationLinkToken(t, fx.sender.last(t))

	resp, err := http.Get(fx.srv.URL + testOrgProject + "/verify-email?token=" + plaintext)
	if err != nil {
		t.Fatalf("verify-email: %v", err)
	}
	if resp.StatusCode != 200 {
		var body map[string]interface{}
		decodeJSON(resp, &body)
		t.Fatalf("verify-email: got %d, body %v", resp.StatusCode, body)
	}
	resp.Body.Close()

	if !fx.emailVerified(t, aliceEmail) {
		t.Fatal("account should be verified after redeeming the token")
	}
}

func TestIntegration_VerifyEmailAcceptsPostWithJSONBody(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()

	fx.register(t, aliceEmail).Body.Close()
	plaintext := verificationLinkToken(t, fx.sender.last(t))

	resp := postJSON(fx.srv, testOrgProject+"/verify-email", map[string]string{"token": plaintext})
	if resp.StatusCode != 200 {
		t.Fatalf("POST verify-email: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	if !fx.emailVerified(t, aliceEmail) {
		t.Fatal("POST verify-email should verify the account too")
	}
}

func TestIntegration_VerifyEmailRejectsReusedUnknownAndExpiredTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()

	fx.register(t, aliceEmail).Body.Close()
	plaintext := verificationLinkToken(t, fx.sender.last(t))

	first := postJSON(fx.srv, testOrgProject+"/verify-email", map[string]string{"token": plaintext})
	first.Body.Close()

	reused := postJSON(fx.srv, testOrgProject+"/verify-email", map[string]string{"token": plaintext})
	if reused.StatusCode != 400 {
		t.Errorf("reused token: got %d, want 400", reused.StatusCode)
	}
	reused.Body.Close()

	unknown := postJSON(fx.srv, testOrgProject+"/verify-email", map[string]string{"token": "not-a-real-token"})
	if unknown.StatusCode != 400 {
		t.Errorf("unknown token: got %d, want 400", unknown.StatusCode)
	}
	unknown.Body.Close()

	empty := postJSON(fx.srv, testOrgProject+"/verify-email", map[string]string{"token": ""})
	if empty.StatusCode != 400 {
		t.Errorf("empty token: got %d, want 400", empty.StatusCode)
	}
	empty.Body.Close()

	// Expired: mint a fresh token, then backdate it past its expiry.
	fx.sender.reset()
	resend := postJSON(fx.srv, testOrgProject+"/resend-verification", map[string]string{"email": aliceEmail})
	resend.Body.Close()
	if len(fx.sender.all()) == 0 {
		t.Skip("account already verified, resend sends nothing")
	}
	expiring := verificationLinkToken(t, fx.sender.last(t))
	fx.db.Exec(context.Background(),
		"UPDATE auth.email_verification_tokens SET expires_at = NOW() - INTERVAL '1 minute' WHERE token_hash = $1",
		token.Hash(expiring))

	expired := postJSON(fx.srv, testOrgProject+"/verify-email", map[string]string{"token": expiring})
	if expired.StatusCode != 400 {
		t.Errorf("expired token: got %d, want 400", expired.StatusCode)
	}
	expired.Body.Close()
}

// === login gating ===

func TestIntegration_LoginBlockedWhileUnverifiedWhenProjectRequiresIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, true)
	defer cleanup()

	registerResp := fx.register(t, aliceEmail)
	if registerResp.StatusCode != 201 {
		t.Fatalf("register: got %d", registerResp.StatusCode)
	}
	var registerBody map[string]interface{}
	decodeJSON(registerResp, &registerBody)
	// Handing back a usable session here would defeat the requirement.
	if registerBody["accessToken"] != nil && registerBody["accessToken"] != "" {
		t.Error("register must not return an access token when verification is required")
	}
	if registerBody["emailVerificationRequired"] != true {
		t.Errorf("register should flag that verification is required, got %v", registerBody)
	}

	login := postJSON(fx.srv, testOrgProject+"/login", map[string]string{
		"email": aliceEmail, "password": alicePassword,
	})
	if login.StatusCode != 403 {
		t.Fatalf("login while unverified: got %d, want 403", login.StatusCode)
	}
	var loginBody map[string]interface{}
	decodeJSON(login, &loginBody)
	if loginBody["error"] != errEmailNotVerified.Error() {
		t.Errorf("error code: got %v, want %q", loginBody["error"], errEmailNotVerified.Error())
	}

	grant := postJSON(fx.srv, testOrgProject+"/token", map[string]string{
		"grant_type": "password", "email": aliceEmail, "password": alicePassword,
	})
	if grant.StatusCode != 403 {
		t.Errorf("/token password grant while unverified: got %d, want 403", grant.StatusCode)
	}
	grant.Body.Close()

	// Verify, then the same credentials work.
	plaintext := verificationLinkToken(t, fx.sender.last(t))
	postJSON(fx.srv, testOrgProject+"/verify-email", map[string]string{"token": plaintext}).Body.Close()

	after := postJSON(fx.srv, testOrgProject+"/login", map[string]string{
		"email": aliceEmail, "password": alicePassword,
	})
	if after.StatusCode != 200 {
		t.Fatalf("login after verification: got %d, want 200", after.StatusCode)
	}
	after.Body.Close()
}

func TestIntegration_LoginAllowedWhileUnverifiedByDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()

	fx.register(t, aliceEmail).Body.Close()

	login := postJSON(fx.srv, testOrgProject+"/login", map[string]string{
		"email": aliceEmail, "password": alicePassword,
	})
	if login.StatusCode != 200 {
		t.Fatalf("login should succeed when the project does not require verification: got %d", login.StatusCode)
	}
	login.Body.Close()
}

func TestIntegration_TokenCarriesEmailVerifiedClaim(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()

	fx.register(t, aliceEmail).Body.Close()
	plaintext := verificationLinkToken(t, fx.sender.last(t))

	before := postJSON(fx.srv, testOrgProject+"/login", map[string]string{
		"email": aliceEmail, "password": alicePassword,
	})
	var beforeBody map[string]interface{}
	decodeJSON(before, &beforeBody)
	if claimsOf(t, beforeBody["accessToken"].(string))["email_verified"] != false {
		t.Error("email_verified should be false before verification")
	}

	postJSON(fx.srv, testOrgProject+"/verify-email", map[string]string{"token": plaintext}).Body.Close()

	after := postJSON(fx.srv, testOrgProject+"/login", map[string]string{
		"email": aliceEmail, "password": alicePassword,
	})
	var afterBody map[string]interface{}
	decodeJSON(after, &afterBody)
	if claimsOf(t, afterBody["accessToken"].(string))["email_verified"] != true {
		t.Error("email_verified should be true after verification")
	}
}

// === aud claim end to end ===

func TestIntegration_MintedTokensCarryProjectAudience(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()

	resp := fx.register(t, aliceEmail)
	var body map[string]interface{}
	decodeJSON(resp, &body)

	claims := claimsOf(t, body["accessToken"].(string))
	audience, ok := claims["aud"].([]interface{})
	if !ok || len(audience) != 1 || audience[0] != "excalibase:test-project" {
		t.Fatalf("aud: got %v, want [excalibase:test-project]", claims["aud"])
	}
	if claims["token_use"] != auth.TokenUseAccess {
		t.Errorf("token_use: got %v", claims["token_use"])
	}
}

// === resend throttling ===

func TestIntegration_ResendVerificationIsThrottledAndNeverEnumerates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()

	fx.register(t, aliceEmail).Body.Close()
	fx.sender.reset()

	for i := 1; i <= resendVerificationLimit; i++ {
		resp := postJSON(fx.srv, testOrgProject+"/resend-verification", map[string]string{"email": aliceEmail})
		if resp.StatusCode != 200 {
			t.Fatalf("resend %d: got %d, want 200", i, resp.StatusCode)
		}
		resp.Body.Close()
	}
	if got := len(fx.sender.all()); got != resendVerificationLimit {
		t.Fatalf("emails sent: got %d, want %d", got, resendVerificationLimit)
	}

	over := postJSON(fx.srv, testOrgProject+"/resend-verification", map[string]string{"email": aliceEmail})
	if over.StatusCode != 429 {
		t.Errorf("over-limit resend: got %d, want 429", over.StatusCode)
	}
	over.Body.Close()

	// An unknown address must look exactly like a known one and send nothing.
	fx.sender.reset()
	unknown := postJSON(fx.srv, testOrgProject+"/resend-verification", map[string]string{"email": "nobody@verify.test"})
	if unknown.StatusCode != 200 {
		t.Errorf("unknown address: got %d, want 200", unknown.StatusCode)
	}
	unknown.Body.Close()
	if got := len(fx.sender.all()); got != 0 {
		t.Errorf("unknown address must trigger no email, got %d", got)
	}
}

func TestIntegration_ResendVerificationInvalidatesThePreviousToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()

	fx.register(t, aliceEmail).Body.Close()
	first := verificationLinkToken(t, fx.sender.last(t))

	postJSON(fx.srv, testOrgProject+"/resend-verification", map[string]string{"email": aliceEmail}).Body.Close()
	second := verificationLinkToken(t, fx.sender.last(t))

	if first == second {
		t.Fatal("resend must mint a new token")
	}

	stale := postJSON(fx.srv, testOrgProject+"/verify-email", map[string]string{"token": first})
	if stale.StatusCode != 400 {
		t.Errorf("superseded token: got %d, want 400", stale.StatusCode)
	}
	stale.Body.Close()

	fresh := postJSON(fx.srv, testOrgProject+"/verify-email", map[string]string{"token": second})
	if fresh.StatusCode != 200 {
		t.Errorf("newest token: got %d, want 200", fresh.StatusCode)
	}
	fresh.Body.Close()
}

// === delivery failure must not break registration ===

func TestIntegration_RegisterSucceedsWhenEmailDeliveryFails(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()

	fx.sender.failNext = true

	resp := fx.register(t, aliceEmail)
	if resp.StatusCode != 201 {
		t.Fatalf("register with a failing mailer: got %d, want 201", resp.StatusCode)
	}
	resp.Body.Close()
}
