package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/excalibase/auth/internal/email"
	"github.com/excalibase/auth/internal/token"
)

const newPassword = "brand-new-password-456"

// postJSONFrom posts with a chosen client IP so per-IP limits can be exercised.
func postJSONFrom(fx *verifyFixture, path, clientIP string, body interface{}) *http.Response {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, fx.srv.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", clientIP)
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func resetLinkToken(t *testing.T, msg email.Message) string {
	t.Helper()
	link := msg.Data["resetUrl"]
	_, raw, found := strings.Cut(link, "token=")
	if !found {
		t.Fatalf("reset url has no token query parameter: %q", link)
	}
	return raw
}

// registerAndForget registers a user and clears captured mail so the next
// message the test reads is the reset email.
func (f *verifyFixture) registerAndForget(t *testing.T) {
	t.Helper()
	f.register(t, aliceEmail).Body.Close()
	f.sender.reset()
}

func (f *verifyFixture) forgotPassword(t *testing.T, address string) *http.Response {
	t.Helper()
	return postJSON(f.srv, testOrgProject+"/forgot-password", map[string]string{"email": address})
}

func (f *verifyFixture) login(t *testing.T, password string) *http.Response {
	t.Helper()
	return postJSON(f.srv, testOrgProject+"/login", map[string]string{
		"email": aliceEmail, "password": password,
	})
}

func TestIntegration_ForgotPasswordEmailsAHashedSingleUseToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()
	fx.registerAndForget(t)

	resp := fx.forgotPassword(t, aliceEmail)
	if resp.StatusCode != 200 {
		t.Fatalf("forgot-password: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	msg := fx.sender.last(t)
	if msg.Template != email.TemplatePasswordReset {
		t.Errorf("template: got %q", msg.Template)
	}
	if msg.To != aliceEmail {
		t.Errorf("recipient: got %q", msg.To)
	}
	plaintext := resetLinkToken(t, msg)
	if !strings.HasPrefix(msg.Data["resetUrl"], "https://site.test/reset-password?token=") {
		t.Errorf("reset url: got %q", msg.Data["resetUrl"])
	}

	var stored string
	if err := fx.db.QueryRow(context.Background(),
		"SELECT token_hash FROM auth.password_reset_tokens").Scan(&stored); err != nil {
		t.Fatalf("read token row: %v", err)
	}
	if stored == plaintext {
		t.Fatal("the raw reset token must never be stored")
	}
	if stored != token.Hash(plaintext) {
		t.Fatal("stored value must be the SHA-256 hash of the emailed token")
	}
}

func TestIntegration_ResetPasswordChangesTheCredential(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()
	fx.registerAndForget(t)

	fx.forgotPassword(t, aliceEmail).Body.Close()
	plaintext := resetLinkToken(t, fx.sender.last(t))

	reset := postJSON(fx.srv, testOrgProject+"/reset-password", map[string]string{
		"token": plaintext, "newPassword": newPassword,
	})
	if reset.StatusCode != 200 {
		var body map[string]interface{}
		decodeJSON(reset, &body)
		t.Fatalf("reset-password: got %d, body %v", reset.StatusCode, body)
	}
	reset.Body.Close()

	old := fx.login(t, alicePassword)
	if old.StatusCode != 401 {
		t.Errorf("old password should be rejected: got %d", old.StatusCode)
	}
	old.Body.Close()

	fresh := fx.login(t, newPassword)
	if fresh.StatusCode != 200 {
		t.Errorf("new password should work: got %d", fresh.StatusCode)
	}
	fresh.Body.Close()
}

func TestIntegration_ResetPasswordRevokesEveryExistingSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()
	fx.registerAndForget(t)

	// Two live sessions before the reset.
	var refreshTokens []string
	for i := 0; i < 2; i++ {
		resp := fx.login(t, alicePassword)
		var body map[string]interface{}
		decodeJSON(resp, &body)
		refreshTokens = append(refreshTokens, body["refreshToken"].(string))
	}

	fx.forgotPassword(t, aliceEmail).Body.Close()
	plaintext := resetLinkToken(t, fx.sender.last(t))
	postJSON(fx.srv, testOrgProject+"/reset-password", map[string]string{
		"token": plaintext, "newPassword": newPassword,
	}).Body.Close()

	for i, refreshToken := range refreshTokens {
		resp := postJSON(fx.srv, testOrgProject+"/refresh", map[string]string{"refreshToken": refreshToken})
		if resp.StatusCode != 401 {
			t.Errorf("session %d should be revoked after a reset: got %d", i, resp.StatusCode)
		}
		resp.Body.Close()
	}

	var live int
	fx.db.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM auth.refresh_tokens WHERE revoked = false").Scan(&live)
	if live != 0 {
		t.Errorf("expected every refresh token revoked, %d still live", live)
	}
}

func TestIntegration_ResetTokenCannotBeReplayed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()
	fx.registerAndForget(t)

	fx.forgotPassword(t, aliceEmail).Body.Close()
	plaintext := resetLinkToken(t, fx.sender.last(t))

	first := postJSON(fx.srv, testOrgProject+"/reset-password", map[string]string{
		"token": plaintext, "newPassword": newPassword,
	})
	first.Body.Close()

	replay := postJSON(fx.srv, testOrgProject+"/reset-password", map[string]string{
		"token": plaintext, "newPassword": "yet-another-password",
	})
	if replay.StatusCode != 400 {
		t.Errorf("replayed reset token: got %d, want 400", replay.StatusCode)
	}
	replay.Body.Close()

	// The replay must not have taken effect.
	stillNew := fx.login(t, newPassword)
	if stillNew.StatusCode != 200 {
		t.Errorf("password should still be the first reset value: got %d", stillNew.StatusCode)
	}
	stillNew.Body.Close()
}

func TestIntegration_ResetPasswordRejectsUnknownAndExpiredTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()
	fx.registerAndForget(t)

	unknown := postJSON(fx.srv, testOrgProject+"/reset-password", map[string]string{
		"token": "not-a-real-token", "newPassword": newPassword,
	})
	if unknown.StatusCode != 400 {
		t.Errorf("unknown token: got %d, want 400", unknown.StatusCode)
	}
	unknown.Body.Close()

	fx.forgotPassword(t, aliceEmail).Body.Close()
	plaintext := resetLinkToken(t, fx.sender.last(t))
	fx.db.Exec(context.Background(),
		"UPDATE auth.password_reset_tokens SET expires_at = NOW() - INTERVAL '1 minute' WHERE token_hash = $1",
		token.Hash(plaintext))

	expired := postJSON(fx.srv, testOrgProject+"/reset-password", map[string]string{
		"token": plaintext, "newPassword": newPassword,
	})
	if expired.StatusCode != 400 {
		t.Errorf("expired token: got %d, want 400", expired.StatusCode)
	}
	expired.Body.Close()

	// The credential must be untouched.
	unchanged := fx.login(t, alicePassword)
	if unchanged.StatusCode != 200 {
		t.Errorf("password should be unchanged after failed resets: got %d", unchanged.StatusCode)
	}
	unchanged.Body.Close()
}

func TestIntegration_ResetPasswordEnforcesTheRegisterPasswordPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()
	fx.registerAndForget(t)

	fx.forgotPassword(t, aliceEmail).Body.Close()
	plaintext := resetLinkToken(t, fx.sender.last(t))

	empty := postJSON(fx.srv, testOrgProject+"/reset-password", map[string]string{
		"token": plaintext, "newPassword": "",
	})
	if empty.StatusCode != 400 {
		t.Errorf("empty password: got %d, want 400", empty.StatusCode)
	}
	empty.Body.Close()

	// A rejected attempt must not burn the token.
	good := postJSON(fx.srv, testOrgProject+"/reset-password", map[string]string{
		"token": plaintext, "newPassword": newPassword,
	})
	if good.StatusCode != 200 {
		t.Errorf("token should survive a policy rejection: got %d", good.StatusCode)
	}
	good.Body.Close()
}

func TestIntegration_ForgotPasswordInvalidatesPreviousResetTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()
	fx.registerAndForget(t)

	fx.forgotPassword(t, aliceEmail).Body.Close()
	first := resetLinkToken(t, fx.sender.last(t))

	fx.forgotPassword(t, aliceEmail).Body.Close()
	second := resetLinkToken(t, fx.sender.last(t))

	if first == second {
		t.Fatal("a second request must mint a new token")
	}

	stale := postJSON(fx.srv, testOrgProject+"/reset-password", map[string]string{
		"token": first, "newPassword": newPassword,
	})
	if stale.StatusCode != 400 {
		t.Errorf("superseded reset token: got %d, want 400", stale.StatusCode)
	}
	stale.Body.Close()

	fresh := postJSON(fx.srv, testOrgProject+"/reset-password", map[string]string{
		"token": second, "newPassword": newPassword,
	})
	if fresh.StatusCode != 200 {
		t.Errorf("newest reset token: got %d, want 200", fresh.StatusCode)
	}
	fresh.Body.Close()
}

func TestIntegration_ForgotPasswordDoesNotEnumerateAccounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()
	fx.registerAndForget(t)

	known := fx.forgotPassword(t, aliceEmail)
	var knownBody map[string]interface{}
	decodeJSON(known, &knownBody)
	fx.sender.reset()

	unknown := fx.forgotPassword(t, "nobody@verify.test")
	var unknownBody map[string]interface{}
	decodeJSON(unknown, &unknownBody)

	if known.StatusCode != unknown.StatusCode {
		t.Errorf("status differs: known %d, unknown %d", known.StatusCode, unknown.StatusCode)
	}
	if knownBody["message"] != unknownBody["message"] {
		t.Errorf("body differs: known %v, unknown %v", knownBody, unknownBody)
	}
	if got := len(fx.sender.all()); got != 0 {
		t.Errorf("an unknown address must trigger no email, got %d", got)
	}
}

func TestIntegration_ForgotPasswordIsThrottledPerAddressAndPerIP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()
	fx.registerAndForget(t)

	for i := 1; i <= forgotPasswordLimit; i++ {
		resp := postJSONFrom(fx, testOrgProject+"/forgot-password", "203.0.113.5",
			map[string]string{"email": aliceEmail})
		if resp.StatusCode != 200 {
			t.Fatalf("attempt %d: got %d, want 200", i, resp.StatusCode)
		}
		resp.Body.Close()
	}

	overPerAddress := postJSONFrom(fx, testOrgProject+"/forgot-password", "203.0.113.99",
		map[string]string{"email": aliceEmail})
	if overPerAddress.StatusCode != 429 {
		t.Errorf("same address from a new IP: got %d, want 429", overPerAddress.StatusCode)
	}
	overPerAddress.Body.Close()

	overPerIP := postJSONFrom(fx, testOrgProject+"/forgot-password", "203.0.113.5",
		map[string]string{"email": "someone.else@verify.test"})
	if overPerIP.StatusCode != 429 {
		t.Errorf("same IP with a new address: got %d, want 429", overPerIP.StatusCode)
	}
	overPerIP.Body.Close()
}

func TestIntegration_ResetPasswordRequiresBothFields(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()

	missingToken := postJSON(fx.srv, testOrgProject+"/reset-password", map[string]string{
		"newPassword": newPassword,
	})
	if missingToken.StatusCode != 400 {
		t.Errorf("missing token: got %d, want 400", missingToken.StatusCode)
	}
	missingToken.Body.Close()

	badJSON, _ := http.Post(fx.srv.URL+testOrgProject+"/reset-password", "application/json",
		strings.NewReader("not json"))
	if badJSON.StatusCode != 400 {
		t.Errorf("malformed body: got %d, want 400", badJSON.StatusCode)
	}
	badJSON.Body.Close()
}
