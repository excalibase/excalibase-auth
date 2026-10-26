package handler

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/email"
	"github.com/excalibase/auth/internal/middleware"
	"github.com/excalibase/auth/internal/oauth"
)

// otpFixture is the provider fixture with its mail captured and sent inline.
type otpFixture struct {
	*oauthFixture
	sender *stubSender
}

func withCapturedMail(sender *stubSender) func(*AuthHandler) {
	return func(h *AuthHandler) {
		h.SetEmail(sender, "")
		h.dispatchMail = func(send func()) { send() }
		h.otpLimits.MinInterval = testOTPInterval
		h.otpLimits.PerIPDay = 1000
	}
}

func newPostgresOTPFixture(t *testing.T, tune ...func(*AuthHandler)) *otpFixture {
	sender := &stubSender{}
	return &otpFixture{oauthFixture: newPostgresOAuthFixture(t, append([]func(*AuthHandler){withCapturedMail(sender)}, tune...)...), sender: sender}
}

func newMySQLOTPFixture(t *testing.T) *otpFixture {
	sender := &stubSender{}
	return &otpFixture{oauthFixture: newMySQLOAuthFixture(t, withCapturedMail(sender)), sender: sender}
}

func TestIntegration_EmailSignInOnPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	runEmailSignInFlows(t, newPostgresOTPFixture(t))
}

func TestIntegration_EmailSignInOnMySQL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	runEmailSignInFlows(t, newMySQLOTPFixture(t))
}

func TestIntegration_EmailSignUpsSpendTheProjectSignUpBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	limits := middleware.NewRateLimits(middleware.RateLimitConfig{
		Window: time.Hour, RegisterPerIP: 100, LoginPerIP: 100, TokenPerIP: 100, OTPPerIP: 100,
		RegisterPerProject: 1, LoginFailures: 100, FailureWindow: time.Hour,
	})
	fx := newPostgresOTPFixture(t, func(h *AuthHandler) { h.WithRateLimits(limits) })
	fx.signInWithCode(t, mailbox("budget"))
	verifier := fx.sendCode(t, mailbox("over-budget"))
	resp, body := fx.verifyCode(mailbox("over-budget"), fx.lastCode(t), verifier)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a sign-up past the project's budget: %d %v", resp.StatusCode, body)
	}
}

func TestIntegration_EmailSendsPastTheBudgetsAreHeldBack(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx := newPostgresOTPFixture(t, func(h *AuthHandler) { h.otpLimits.PerProjectDay, h.otpLimits.PerIPDay = 1, 3 })
	fx.sendCode(t, mailbox("budget-first"))
	fx.sender.reset()
	fx.sendCode(t, mailbox("budget-second"))
	if len(fx.sender.all()) != 0 {
		t.Fatal("a send past the project's daily budget was mailed")
	}
	fx.sendCode(t, mailbox("budget-third"))
	resp, body := fx.requestOTP(map[string]any{"email": mailbox("budget-fourth"), "type": "email",
		"code_challenge": oauth.S256(newVerifier(t)), "code_challenge_method": "S256"})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a send past the client's daily budget: %d %s", resp.StatusCode, body)
	}
}

var mailboxSeq = map[string]int{}

// mailbox is a stable address per name within one test binary run.
func mailbox(name string) string {
	if _, ok := mailboxSeq[name]; !ok {
		mailboxSeq[name] = int(oauthSeq.Add(1))
	}
	return fmt.Sprintf("%s-%d@otp.test", name, mailboxSeq[name])
}

func runEmailSignInFlows(t *testing.T, fx *otpFixture) {
	t.Run("ACodeSignsUpThenSignsInToTheSameAccount", func(t *testing.T) { otpCodeSignUpThenIn(t, fx) })
	t.Run("AMagicLinkSignsInOnlyWithTheBrowsersVerifier", func(t *testing.T) { otpMagicLink(t, fx) })
	t.Run("ACodeDiesAfterFiveWrongTries", func(t *testing.T) { otpAttempts(t, fx) })
	t.Run("TheAnswerIsTheSameWhetherOrNotTheAccountExists", func(t *testing.T) { otpNoEnumeration(t, fx) })
	t.Run("AnAddressWaitsBetweenSends", func(t *testing.T) { otpPaced(t, fx) })
	t.Run("ClosedSignUpsCreateNoAccount", func(t *testing.T) { otpSignUpsClosed(t, fx) })
	t.Run("AnUnverifiedAccountIsTakenOverByTheInboxOwner", func(t *testing.T) { otpTakeover(t, fx) })
	t.Run("ADisabledAccountIsNeitherSignedInToNorReplaced", func(t *testing.T) { otpDisabled(t, fx) })
	t.Run("GuessesFromAnotherBrowserDoNotSpendACode", func(t *testing.T) { otpGuessesNeedTheChallenge(t, fx) })
	t.Run("RequestsAreCheckedBeforeAnythingIsSent", func(t *testing.T) { otpRefusals(t, fx) })
	t.Run("OffOrUnreadableSettingsRefuseBothRoutes", func(t *testing.T) { otpFailsClosed(t, fx) })
}

func newVerifier(t *testing.T) string {
	t.Helper()
	flow, err := oauth.NewFlow()
	if err != nil {
		t.Fatal(err)
	}
	return flow.Verifier
}

func (fx *otpFixture) requestOTP(body map[string]any) (*http.Response, string) {
	resp := postJSON(fx.srv, oauthProject+"/otp", body)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(raw)
}

// sendCode asks for a code for the address and returns the verifier kept.
func (fx *otpFixture) sendCode(t *testing.T, address string) string {
	t.Helper()
	verifier := newVerifier(t)
	resp, body := fx.requestOTP(map[string]any{"email": address, "type": "email", "create_user": true,
		"code_challenge": oauth.S256(verifier), "code_challenge_method": "S256"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send code: %d %s", resp.StatusCode, body)
	}
	return verifier
}

func (fx *otpFixture) lastCode(t *testing.T) string {
	t.Helper()
	msg := fx.sender.last(t)
	if msg.Template != email.TemplateEmailOTP || msg.ProjectID != "test-project" {
		t.Fatalf("mail = %s for %s", msg.Template, msg.ProjectID)
	}
	return msg.Data["code"]
}

func (fx *otpFixture) verify(body map[string]any) (*http.Response, map[string]any) {
	resp := postJSON(fx.srv, oauthProject+"/verify", body)
	var decoded map[string]any
	decodeJSON(resp, &decoded)
	return resp, decoded
}

func (fx *otpFixture) verifyCode(address, code, verifier string) (*http.Response, map[string]any) {
	return fx.verify(map[string]any{"type": "email", "email": address, "token": code, "code_verifier": verifier})
}

func (fx *otpFixture) signInWithCode(t *testing.T, address string) map[string]any {
	t.Helper()
	verifier := fx.sendCode(t, address)
	resp, body := fx.verifyCode(address, fx.lastCode(t), verifier)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify code: %d %v", resp.StatusCode, body)
	}
	return body
}

func otpCodeSignUpThenIn(t *testing.T, fx *otpFixture) {
	address := mailbox("code")
	verifier := fx.sendCode(t, address)
	auditRows := fx.count(t, "audit_log")
	msg := fx.sender.last(t)
	code := fx.lastCode(t)
	if msg.To != address || len(code) != 6 || msg.Data["expiresMin"] != "10" {
		t.Fatalf("mail = %+v", msg.Data)
	}
	resp, first := fx.verifyCode(strings.ToUpper(address), code, verifier)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify: %d %v", resp.StatusCode, first)
	}
	claims := jwtPayload(t, first["accessToken"].(string))
	if claims["sub"] != address || claims["email_verified"] != true || claims["role"] != "user" || first["refreshToken"] == "" {
		t.Fatalf("claims = %v", claims)
	}
	if !fx.passwordIsNull(t, address) {
		t.Fatal("an account made by a code has a password")
	}
	if resp, _ := fx.verifyCode(address, code, verifier); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a code was spent twice: %d", resp.StatusCode)
	}
	otpWait(t, fx)
	if again := fx.signInWithCode(t, address); userIDOf(again) != userIDOf(first) {
		t.Fatalf("second sign-in reached %v, want %v", userIDOf(again), userIDOf(first))
	}
	if got := fx.count(t, "audit_log"); got != auditRows+2 {
		t.Fatalf("audit_log grew by %d, want 2", got-auditRows)
	}
}

func otpMagicLink(t *testing.T, fx *otpFixture) {
	address := mailbox("link")
	send := func() (string, string) {
		verifier := newVerifier(t)
		resp, body := fx.requestOTP(map[string]any{"email": address, "redirect_to": appCallback, "create_user": true,
			"code_challenge": oauth.S256(verifier), "code_challenge_method": "S256"})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("send link: %d %s", resp.StatusCode, body)
		}
		msg := fx.sender.last(t)
		if msg.Template != email.TemplateMagicLink {
			t.Fatalf("template = %s", msg.Template)
		}
		link, err := url.Parse(msg.Data["linkUrl"])
		if err != nil || !strings.HasPrefix(link.String(), appCallback+"?") || link.Query().Get("type") != "magiclink" || link.Fragment != "" {
			t.Fatalf("link = %q", msg.Data["linkUrl"])
		}
		return link.Query().Get("token_hash"), verifier
	}
	tokenHash, verifier := send()
	if resp, _ := fx.verify(map[string]any{"type": "magiclink", "token_hash": tokenHash, "code_verifier": newVerifier(t)}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a link redeemed with another browser's verifier: %d", resp.StatusCode)
	}
	if resp, _ := fx.verify(map[string]any{"type": "magiclink", "token_hash": tokenHash, "code_verifier": verifier}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a link refused once was redeemed after: %d", resp.StatusCode)
	}
	otpWait(t, fx)
	tokenHash, verifier = send()
	resp, body := fx.verify(map[string]any{"type": "magiclink", "token_hash": tokenHash, "code_verifier": verifier})
	if resp.StatusCode != http.StatusOK || jwtPayload(t, body["accessToken"].(string))["sub"] != address {
		t.Fatalf("magic link: %d %v", resp.StatusCode, body)
	}
}

// otpWait lets the address's minimum interval pass.
func otpWait(t *testing.T, _ *otpFixture) {
	t.Helper()
	time.Sleep(testOTPInterval + 50*time.Millisecond)
}

const testOTPInterval = 200 * time.Millisecond

func otpAttempts(t *testing.T, fx *otpFixture) {
	address := mailbox("attempts")
	verifier := fx.sendCode(t, address)
	code := fx.lastCode(t)
	wrong := fmt.Sprintf("%06d", (atoi(code)+1)%1_000_000)
	for i := range 5 {
		if resp, body := fx.verifyCode(address, wrong, verifier); resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_or_expired_token" {
			t.Fatalf("wrong code %d: %d %v", i+1, resp.StatusCode, body)
		}
	}
	if resp, _ := fx.verifyCode(address, code, verifier); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("the right code after five wrong ones: %d", resp.StatusCode)
	}
	otpWait(t, fx)
	verifier = fx.sendCode(t, address)
	if resp, _ := fx.verifyCode(address, fx.lastCode(t), newVerifier(t)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a right code with another browser's verifier: %d", resp.StatusCode)
	}
	if resp, _ := fx.verifyCode(address, fx.lastCode(t), verifier); resp.StatusCode != http.StatusOK {
		t.Fatalf("the right code and verifier after one refusal: %d", resp.StatusCode)
	}
}

func atoi(digits string) int {
	n := 0
	for _, r := range digits {
		n = n*10 + int(r-'0')
	}
	return n
}

func otpNoEnumeration(t *testing.T, fx *otpFixture) {
	known := mailbox("known")
	fx.signInWithCode(t, known)
	otpWait(t, fx)
	ask := func(address string) (int, string) {
		resp, body := fx.requestOTP(map[string]any{"email": address, "type": "email", "create_user": false,
			"code_challenge": oauth.S256(newVerifier(t)), "code_challenge_method": "S256"})
		return resp.StatusCode, body
	}
	fx.sender.reset()
	knownStatus, knownBody := ask(known)
	if len(fx.sender.all()) != 1 {
		t.Fatal("an existing account got no code")
	}
	fx.sender.reset()
	unknownStatus, unknownBody := ask(mailbox("nobody"))
	if len(fx.sender.all()) != 0 {
		t.Fatal("an address without an account got a code with create_user false")
	}
	if knownStatus != http.StatusOK || knownStatus != unknownStatus || knownBody != unknownBody {
		t.Fatalf("known %d %s, unknown %d %s", knownStatus, knownBody, unknownStatus, unknownBody)
	}
	knownStatus, _ = ask(known)
	unknownStatus, _ = ask(mailbox("nobody"))
	if knownStatus != http.StatusTooManyRequests || unknownStatus != knownStatus {
		t.Fatalf("a second send at once: known %d, unknown %d", knownStatus, unknownStatus)
	}
}

func otpPaced(t *testing.T, fx *otpFixture) {
	address := mailbox("paced")
	fx.sendCode(t, address)
	resp, _ := fx.requestOTP(map[string]any{"email": address, "type": "email",
		"code_challenge": oauth.S256(newVerifier(t)), "code_challenge_method": "S256"})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a second send inside the interval: %d", resp.StatusCode)
	}
}

func otpSignUpsClosed(t *testing.T, fx *otpFixture) {
	defer fx.settings.set(func(s *signInSettings) { s.allowNewUsers = true })
	address := mailbox("closed")
	verifier := fx.sendCode(t, address)
	code := fx.lastCode(t)
	fx.settings.set(func(s *signInSettings) { s.allowNewUsers = false })
	if resp, body := fx.verifyCode(address, code, verifier); resp.StatusCode != http.StatusForbidden || body["error"] != "signup_disabled" {
		t.Fatalf("a sign-up after sign-ups closed: %d %v", resp.StatusCode, body)
	}
	fx.sender.reset()
	resp, _ := fx.requestOTP(map[string]any{"email": mailbox("closed-new"), "type": "email", "create_user": true,
		"code_challenge": oauth.S256(newVerifier(t)), "code_challenge_method": "S256"})
	if resp.StatusCode != http.StatusOK || len(fx.sender.all()) != 0 {
		t.Fatalf("closed sign-ups: %d and %d mails", resp.StatusCode, len(fx.sender.all()))
	}
}

func otpTakeover(t *testing.T, fx *otpFixture) {
	address := mailbox("squat")
	reg := postJSON(fx.srv, oauthProject+"/register", map[string]string{"email": address, "password": oauthPassword, "fullName": "Squatter"})
	var squatter map[string]any
	decodeJSON(reg, &squatter)
	if reg.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %v", reg.StatusCode, squatter)
	}
	owner := fx.signInWithCode(t, address)
	if userIDOf(owner) == userIDOf(squatter) || !fx.passwordIsNull(t, address) {
		t.Fatalf("the inbox owner reached the squatter's account %v", userIDOf(owner))
	}
	login := postJSON(fx.srv, oauthProject+"/login", map[string]string{"email": address, "password": oauthPassword})
	login.Body.Close()
	if login.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the squatter's password still signs in: %d", login.StatusCode)
	}
}

func otpDisabled(t *testing.T, fx *otpFixture) {
	address := mailbox("disabled")
	reg := postJSON(fx.srv, oauthProject+"/register", map[string]string{"email": address, "password": oauthPassword, "fullName": "Off"})
	reg.Body.Close()
	if reg.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", reg.StatusCode)
	}
	fx.disable(t, address)
	fx.sender.reset()
	resp, _ := fx.requestOTP(map[string]any{"email": address, "type": "email", "create_user": true,
		"code_challenge": oauth.S256(newVerifier(t)), "code_challenge_method": "S256"})
	if resp.StatusCode != http.StatusOK || len(fx.sender.all()) != 0 {
		t.Fatalf("a disabled account: %d and %d mails", resp.StatusCode, len(fx.sender.all()))
	}
	if fx.passwordIsNull(t, address) {
		t.Fatal("the disabled account was replaced")
	}
}

func otpGuessesNeedTheChallenge(t *testing.T, fx *otpFixture) {
	address := mailbox("victim")
	verifier := fx.sendCode(t, address)
	code := fx.lastCode(t)
	wrong := fmt.Sprintf("%06d", (atoi(code)+1)%1_000_000)
	for range 6 {
		if resp, _ := fx.verifyCode(address, wrong, newVerifier(t)); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("a guess from another browser: %d", resp.StatusCode)
		}
	}
	if resp, body := fx.verifyCode(address, code, verifier); resp.StatusCode != http.StatusOK {
		t.Fatalf("guesses from another browser spent the code: %d %v", resp.StatusCode, body)
	}
}

func otpRefusals(t *testing.T, fx *otpFixture) {
	challenge := oauth.S256(newVerifier(t))
	cases := map[string]struct {
		body map[string]any
		want int
	}{
		"a redirect off the allow-list": {map[string]any{"email": mailbox("r1"), "redirect_to": "https://evil.test/cb",
			"code_challenge": challenge, "code_challenge_method": "S256"}, http.StatusBadRequest},
		"no PKCE challenge":   {map[string]any{"email": mailbox("r2"), "type": "email"}, http.StatusBadRequest},
		"a plain challenge":   {map[string]any{"email": mailbox("r3"), "type": "email", "code_challenge": challenge, "code_challenge_method": "plain"}, http.StatusBadRequest},
		"an unknown type":     {map[string]any{"email": mailbox("r4"), "type": "sms", "code_challenge": challenge, "code_challenge_method": "S256"}, http.StatusBadRequest},
		"no address":          {map[string]any{"type": "email", "code_challenge": challenge, "code_challenge_method": "S256"}, http.StatusBadRequest},
		"a malformed address": {map[string]any{"email": "not an address", "type": "email", "code_challenge": challenge, "code_challenge_method": "S256"}, http.StatusBadRequest},
		"an oversized body":   {map[string]any{"email": mailbox("r5"), "type": "email", "code_challenge": challenge, "code_challenge_method": "S256", "pad": strings.Repeat("x", 64<<10)}, http.StatusBadRequest},
		"an address too long": {map[string]any{"email": strings.Repeat("a", 101) + "@x.test", "type": "email", "code_challenge": challenge, "code_challenge_method": "S256"}, http.StatusBadRequest},
	}
	fx.sender.reset()
	for name, tc := range cases {
		if resp, body := fx.requestOTP(tc.body); resp.StatusCode != tc.want {
			t.Errorf("%s: %d %s", name, resp.StatusCode, body)
		}
	}
	if len(fx.sender.all()) != 0 {
		t.Fatal("a refused request sent mail")
	}
	for name, body := range map[string]map[string]any{
		"an unknown type":    {"type": "sms", "email": mailbox("v1"), "token": "123456", "code_verifier": newVerifier(t)},
		"no verifier":        {"type": "email", "email": mailbox("v2"), "token": "123456"},
		"no token hash":      {"type": "magiclink", "code_verifier": newVerifier(t)},
		"a code, no address": {"type": "email", "token": "123456", "code_verifier": newVerifier(t)},
		"an oversized body":  {"type": "email", "email": mailbox("v3"), "token": "123456", "code_verifier": newVerifier(t), "pad": strings.Repeat("x", 64<<10)},
	} {
		if resp, decoded := fx.verify(body); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("verify with %s: %d %v", name, resp.StatusCode, decoded)
		}
	}
}

func otpFailsClosed(t *testing.T, fx *otpFixture) {
	body := map[string]any{"email": mailbox("off"), "type": "email", "code_challenge": oauth.S256(newVerifier(t)), "code_challenge_method": "S256"}
	verify := map[string]any{"type": "email", "email": mailbox("off"), "token": "123456", "code_verifier": newVerifier(t)}

	fx.settings.set(func(s *signInSettings) { s.emailOTP = false })
	if resp, raw := fx.requestOTP(body); resp.StatusCode != http.StatusNotFound || !strings.Contains(raw, "method_not_enabled") {
		t.Fatalf("send with email sign-in off: %d %s", resp.StatusCode, raw)
	}
	if resp, _ := fx.verify(verify); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("verify with email sign-in off: %d", resp.StatusCode)
	}
	fx.settings.set(func(s *signInSettings) { s.emailOTP, s.infoDown = true, true })
	defer fx.settings.set(func(s *signInSettings) { s.infoDown = false })
	if resp, _ := fx.requestOTP(body); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("send with settings unreadable: %d", resp.StatusCode)
	}
	if resp, _ := fx.verify(verify); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("verify with settings unreadable: %d", resp.StatusCode)
	}
}
