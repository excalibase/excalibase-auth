package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/email"
	"github.com/excalibase/auth/internal/hooks"
	"github.com/excalibase/auth/internal/pool"
)

// hookSecret is the project's signing secret the fake vault hands out.
var hookSecret = "whsec_" + base64.StdEncoding.EncodeToString([]byte("an-auth-hook-signing-key-32bytes"))

// hookCall is one request the fake hook received, signature checked.
type hookCall struct {
	path   string
	signed bool
	body   map[string]any
}

// hookServer is a customer's hook endpoint: each path answers one way.
type hookServer struct {
	*httptest.Server
	mu    sync.Mutex
	calls []hookCall
}

func newHookServer(t *testing.T) *hookServer {
	t.Helper()
	hs := &hookServer{}
	hs.Server = httptest.NewTLSServer(http.HandlerFunc(hs.serve))
	t.Cleanup(hs.Close)
	return hs
}

func (hs *hookServer) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	signed := validSignature(r, raw)
	hs.mu.Lock()
	hs.calls = append(hs.calls, hookCall{path: r.URL.Path, signed: signed, body: body})
	hs.mu.Unlock()
	if !signed {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	claims, _ := body["claims"].(map[string]any)
	switch r.URL.Path {
	case "/claims":
		claims["tenant_id"], claims["groups"] = "acme", []string{"staff"}
		writeJSON(w, map[string]any{"claims": claims})
	case "/role-outside":
		claims["role"] = "admin"
		writeJSON(w, map[string]any{"claims": claims})
	case "/role-service":
		claims["role"] = "service"
		writeJSON(w, map[string]any{"claims": claims})
	case "/forbidden-user":
		claims["userId"] = 999999.0
		writeJSON(w, map[string]any{"claims": claims})
	case "/deny":
		user, _ := body["user"].(map[string]any)
		address, _ := user["email"].(string)
		decision := "deny"
		if strings.HasSuffix(address, "@allowed.test") {
			decision = "allow"
		}
		writeJSON(w, map[string]string{"decision": decision})
	case "/mail":
		w.WriteHeader(http.StatusNoContent)
	case "/slow":
		time.Sleep(hooks.Timeout + time.Second)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// validSignature checks the Standard Webhooks headers as a receiver would.
func validSignature(r *http.Request, body []byte) bool {
	id, stamp := r.Header.Get("webhook-id"), r.Header.Get("webhook-timestamp")
	sent, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil || !strings.HasPrefix(id, "msg_") || time.Since(time.Unix(sent, 0)).Abs() > 5*time.Minute {
		return false
	}
	key, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(hookSecret, "whsec_"))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + stamp + "." + string(body)))
	want := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(r.Header.Get("webhook-signature")), []byte(want))
}

func (hs *hookServer) received(path string) []hookCall {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	var out []hookCall
	for _, call := range hs.calls {
		if call.path == path {
			out = append(out, call)
		}
	}
	return out
}

func (hs *hookServer) url(path string) string { return hs.URL + path }

type hooksFixture struct {
	*otpFixture
	hook *hookServer
}

func newHooksFixture(t *testing.T, mysql bool) *hooksFixture {
	t.Helper()
	hook := newHookServer(t)
	tune := func(h *AuthHandler) { h.WithHooks(hooks.NewClientWith(hook.Client())) }
	var fx *otpFixture
	if mysql {
		fx = newMySQLOTPFixture(t, tune)
	} else {
		fx = newPostgresOTPFixture(t, tune)
	}
	fx.settings.set(func(s *signInSettings) { s.hooks = &pool.AuthHooks{} })
	return &hooksFixture{otpFixture: fx, hook: hook}
}

func (fx *hooksFixture) useHooks(change func(*pool.AuthHooks)) {
	fx.settings.set(func(s *signInSettings) {
		next := pool.AuthHooks{}
		change(&next)
		s.hooks = &next
	})
}

func TestIntegration_AuthHooksOnPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	runHookFlows(t, newHooksFixture(t, false))
}

func TestIntegration_AuthHooksOnMySQL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	runHookFlows(t, newHooksFixture(t, true))
}

func runHookFlows(t *testing.T, fx *hooksFixture) {
	t.Run("CustomClaimsLandInEveryAccessTokenRefreshIncluded", func(t *testing.T) { hookAddsClaims(t, fx) })
	t.Run("ForbiddenClaimChangesFailTheSignInClosed", func(t *testing.T) { hookForbiddenChanges(t, fx) })
	t.Run("AFailingOrSlowHookFailsClosedAndKeepsTheSession", func(t *testing.T) { hookFailsClosed(t, fx) })
	t.Run("UnreadableSettingsFailClosedOnlyWhileHooksAreOn", func(t *testing.T) { hookSettingsFailClosed(t, fx) })
	t.Run("ADeniedPasswordSignUpLooksTheSameForTakenAddresses", func(t *testing.T) { hookDeniesPasswordSignUp(t, fx) })
	t.Run("EveryWayToANewAccountAsksTheHook", func(t *testing.T) { hookDeniesOtherSignUps(t, fx) })
	t.Run("SendEmailDeliversThroughTheHookNeverTheRelay", func(t *testing.T) { hookSendsMail(t, fx) })
}

func hookAddsClaims(t *testing.T, fx *hooksFixture) {
	fx.useHooks(func(h *pool.AuthHooks) { h.CustomAccessToken = fx.hook.url("/claims") })
	defer fx.useHooks(func(*pool.AuthHooks) {})
	session, address := fx.passwordAccount(t, "hook-claims")
	claims := jwtPayload(t, accessTokenOf(session))
	if claims["tenant_id"] != "acme" || claims["role"] != "user" || claims["email"] != address {
		t.Fatalf("claims = %v", claims)
	}
	if groups, _ := claims["groups"].([]any); len(groups) != 1 || groups[0] != "staff" {
		t.Fatalf("groups = %v", claims["groups"])
	}
	resp, refreshed := fx.refreshWith(refreshTokenOf(session))
	if resp.StatusCode != http.StatusOK || jwtPayload(t, accessTokenOf(refreshed))["tenant_id"] != "acme" {
		t.Fatalf("refresh: %d %v", resp.StatusCode, refreshed)
	}
	calls := fx.hook.received("/claims")
	last := calls[len(calls)-1]
	sent, _ := last.body["claims"].(map[string]any)
	if !last.signed || last.body["type"] != "custom_access_token" || last.body["projectId"] != "test-project" ||
		last.body["userId"] != userIDOf(session) || sent["projectId"] != "test-project" {
		t.Fatalf("hook call = %+v", last)
	}
	if _, timed := sent["exp"]; timed {
		t.Fatalf("the hook was shown exp: %v", sent)
	}
}

func hookForbiddenChanges(t *testing.T, fx *hooksFixture) {
	_, address := fx.passwordAccount(t, "hook-forbidden")
	for _, path := range []string{"/forbidden-user", "/role-service", "/role-outside"} {
		fx.useHooks(func(h *pool.AuthHooks) { h.CustomAccessToken = fx.hook.url(path) })
		resp, body := fx.call(http.MethodPost, oauthProject+"/login", "", map[string]string{"email": address, "password": oauthPassword})
		if resp.StatusCode != http.StatusServiceUnavailable || body["error"] != codeHookFailed || accessTokenOf(body) != "" {
			t.Fatalf("%s: %d %v", path, resp.StatusCode, body)
		}
	}
	fx.useHooks(func(*pool.AuthHooks) {})
	if got := fx.countAudit(t, "hook_failed"); got < 3 {
		t.Fatalf("hook_failed audit rows = %d", got)
	}
}

func hookFailsClosed(t *testing.T, fx *hooksFixture) {
	session, address := fx.passwordAccount(t, "hook-fails")
	for _, path := range []string{"/fail", "/slow"} {
		fx.useHooks(func(h *pool.AuthHooks) { h.CustomAccessToken = fx.hook.url(path) })
		started := time.Now()
		resp, body := fx.call(http.MethodPost, oauthProject+"/login", "", map[string]string{"email": address, "password": oauthPassword})
		if resp.StatusCode != http.StatusServiceUnavailable || body["error"] != codeHookFailed || time.Since(started) > hooks.Timeout+time.Second {
			t.Fatalf("%s login: %d %v after %v", path, resp.StatusCode, body, time.Since(started))
		}
		resp, body = fx.refreshWith(refreshTokenOf(session))
		if resp.StatusCode != http.StatusServiceUnavailable || body["error"] != codeHookFailed {
			t.Fatalf("%s refresh: %d %v", path, resp.StatusCode, body)
		}
	}
	fx.useHooks(func(h *pool.AuthHooks) { h.CustomAccessToken = "https://127.0.0.1:1/unreachable" })
	if resp, body := fx.refreshWith(refreshTokenOf(session)); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unreachable: %d %v", resp.StatusCode, body)
	}
	fx.useHooks(func(h *pool.AuthHooks) { h.CustomAccessToken = fx.hook.url("/claims") })
	fx.settings.set(func(s *signInSettings) { s.hookSecretMissing = true })
	if resp, body := fx.refreshWith(refreshTokenOf(session)); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("no secret: %d %v", resp.StatusCode, body)
	}
	fx.settings.set(func(s *signInSettings) { s.hookSecretMissing = false })
	// The refused refreshes left the token alone, so the user is still signed in.
	resp, body := fx.refreshWith(refreshTokenOf(session))
	if resp.StatusCode != http.StatusOK || jwtPayload(t, accessTokenOf(body))["tenant_id"] != "acme" {
		t.Fatalf("refresh after the hook recovered: %d %v", resp.StatusCode, body)
	}
	fx.useHooks(func(*pool.AuthHooks) {})
}

func hookSettingsFailClosed(t *testing.T, fx *hooksFixture) {
	_, address := fx.passwordAccount(t, "hook-settings")
	login := func() (*http.Response, map[string]any) {
		return fx.call(http.MethodPost, oauthProject+"/login", "", map[string]string{"email": address, "password": oauthPassword})
	}
	fx.settings.set(func(s *signInSettings) { s.infoDown = true })
	if resp, body := login(); resp.StatusCode != http.StatusServiceUnavailable || body["error"] != codeHookFailed {
		t.Fatalf("hooks on, settings down: %d %v", resp.StatusCode, body)
	}
	// With the flag off nothing changes for sign-in when the control plane is down.
	fx.settings.set(func(s *signInSettings) { s.infoDown, s.hooks = false, nil })
	if resp, body := login(); resp.StatusCode != http.StatusOK {
		t.Fatalf("hooks off: %d %v", resp.StatusCode, body)
	}
	fx.settings.set(func(s *signInSettings) { s.infoDown = true })
	if resp, body := login(); resp.StatusCode != http.StatusOK {
		t.Fatalf("hooks off, settings down: %d %v", resp.StatusCode, body)
	}
	fx.settings.set(func(s *signInSettings) { s.infoDown, s.hooks = false, &pool.AuthHooks{} })
	if resp, _ := login(); resp.StatusCode != http.StatusOK {
		t.Fatalf("hooks on again: %d", resp.StatusCode)
	}
}

func hookDeniesPasswordSignUp(t *testing.T, fx *hooksFixture) {
	_, taken := fx.passwordAccount(t, "hook-taken")
	fx.useHooks(func(h *pool.AuthHooks) { h.BeforeUserCreated = fx.hook.url("/deny") })
	defer fx.useHooks(func(*pool.AuthHooks) {})
	register := func(address string) (*http.Response, map[string]any) {
		return fx.call(http.MethodPost, oauthProject+"/register", "", map[string]string{"email": address, "password": oauthPassword, "fullName": "N"})
	}
	before := fx.count(t, "users")
	fresh, freshBody := register(mailbox("hook-denied"))
	again, takenBody := register(taken)
	if fresh.StatusCode != http.StatusForbidden || again.StatusCode != http.StatusForbidden ||
		freshBody["error"] != codeSignupDenied || takenBody["error"] != codeSignupDenied {
		t.Fatalf("new: %d %v; taken: %d %v", fresh.StatusCode, freshBody, again.StatusCode, takenBody)
	}
	if fx.count(t, "users") != before {
		t.Fatal("a denied sign-up made an account")
	}
	calls := fx.hook.received("/deny")
	last := calls[len(calls)-1]
	if !last.signed || last.body["type"] != "before_user_created" || last.body["method"] != "password" || len(calls) != 2 {
		t.Fatalf("calls = %+v", calls)
	}
	if resp, body := register(strings.Replace(mailbox("hook-allowed"), "@otp.test", "@allowed.test", 1)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("allowed: %d %v", resp.StatusCode, body)
	}
	fx.useHooks(func(h *pool.AuthHooks) { h.BeforeUserCreated = fx.hook.url("/fail") })
	if resp, body := register(mailbox("hook-down")); resp.StatusCode != http.StatusServiceUnavailable || body["error"] != codeHookFailed {
		t.Fatalf("failing hook: %d %v", resp.StatusCode, body)
	}
}

func hookDeniesOtherSignUps(t *testing.T, fx *hooksFixture) {
	on := true
	fx.useHooks(func(h *pool.AuthHooks) { h.BeforeUserCreated = fx.hook.url("/deny") })
	fx.settings.set(func(s *signInSettings) { s.guests = &on })
	defer fx.settings.set(func(s *signInSettings) { s.guests, s.hooks = nil, &pool.AuthHooks{} })

	if resp, body := fx.call(http.MethodPost, guestPath, "", map[string]string{}); resp.StatusCode != http.StatusForbidden || body["error"] != codeSignupDenied {
		t.Fatalf("guest: %d %v", resp.StatusCode, body)
	}
	landed, _ := fx.browserSignIn(t, "github", person("hook-oauth"))
	if landed.Query().Get("error") != codeSignupDenied || landed.Query().Get("code") != "" {
		t.Fatalf("oauth landed on %s", landed)
	}
	address := mailbox("hook-otp")
	verifier := fx.sendCode(t, address)
	if resp, body := fx.verifyCode(address, fx.lastCode(t), verifier); resp.StatusCode != http.StatusForbidden || body["error"] != codeSignupDenied {
		t.Fatalf("email code: %d %v", resp.StatusCode, body)
	}
	methods := map[string]bool{}
	for _, call := range fx.hook.received("/deny") {
		method, _ := call.body["method"].(string)
		methods[method] = true
	}
	if !methods["guest"] || !methods["oauth"] || !methods["email"] {
		t.Fatalf("methods asked = %v", methods)
	}
	// An existing account signs in by code without asking the hook.
	fx.useHooks(func(*pool.AuthHooks) {})
	fx.signInWithCode(t, mailbox("hook-otp-existing"))
	asked := len(fx.hook.received("/deny"))
	fx.useHooks(func(h *pool.AuthHooks) { h.BeforeUserCreated = fx.hook.url("/deny") })
	time.Sleep(testOTPInterval)
	fx.signInWithCode(t, mailbox("hook-otp-existing"))
	if len(fx.hook.received("/deny")) != asked {
		t.Fatal("signing in to an existing account asked before_user_created")
	}
}

func hookSendsMail(t *testing.T, fx *hooksFixture) {
	address := mailbox("hook-mail")
	fx.signInWithCode(t, address)
	fx.useHooks(func(h *pool.AuthHooks) { h.SendEmail = fx.hook.url("/mail") })
	defer fx.useHooks(func(*pool.AuthHooks) {})
	fx.sender.reset()
	time.Sleep(testOTPInterval)
	fx.sendCode(t, address)
	if len(fx.sender.all()) != 0 {
		t.Fatal("the relay sent mail while send_email is on")
	}
	calls := fx.hook.received("/mail")
	last := calls[len(calls)-1]
	mail, _ := last.body["email"].(map[string]any)
	data, _ := mail["data"].(map[string]any)
	if !last.signed || last.body["type"] != "send_email" || mail["to"] != address || mail["template"] != email.TemplateEmailOTP || data["code"] == "" {
		t.Fatalf("hook call = %+v", last)
	}
	fx.useHooks(func(h *pool.AuthHooks) { h.SendEmail = fx.hook.url("/fail") })
	time.Sleep(testOTPInterval)
	resp, body := fx.requestOTP(map[string]any{"email": address, "type": "email", "create_user": true,
		"code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256"})
	if resp.StatusCode != http.StatusOK || len(fx.sender.all()) != 0 {
		t.Fatalf("failing mail hook: %d %s, relay = %d", resp.StatusCode, body, len(fx.sender.all()))
	}
}
