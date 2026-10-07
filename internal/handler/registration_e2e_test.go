package handler

import (
	"io"
	"net/http"
	"testing"
)

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(raw)
}

// A project that signs users in at sign-up has no use for a verification mail.
func TestIntegration_RegisterSendsNoVerificationMailWhenNotRequired(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()

	resp := fx.register(t, aliceEmail)
	var body map[string]interface{}
	decodeJSON(resp, &body)
	if resp.StatusCode != 201 || body["accessToken"] == nil {
		t.Fatalf("register: got %d %v, want 201 with a session", resp.StatusCode, body)
	}
	if sent := fx.sender.all(); len(sent) != 0 {
		t.Errorf("no verification mail expected, got %d", len(sent))
	}
}

// With verification required, sign-up for an existing address answers exactly
// like a new one, mails nothing, and leaves the account's password alone.
func TestIntegration_RegisterDoesNotRevealExistingAccountsWhenVerificationRequired(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, true)
	defer cleanup()

	fresh := fx.register(t, aliceEmail)
	freshStatus, freshBody := fresh.StatusCode, readBody(t, fresh)
	link := verificationLinkToken(t, fx.sender.last(t))
	fx.sender.reset()

	again := postJSON(fx.srv, testOrgProject+"/register", map[string]string{
		"email": aliceEmail, "password": "attacker-chosen-password", "fullName": "Alice",
	})
	againStatus, againBody := again.StatusCode, readBody(t, again)

	if freshStatus != 201 || againStatus != freshStatus {
		t.Errorf("status: new %d, existing %d; want both 201", freshStatus, againStatus)
	}
	if againBody != freshBody {
		t.Errorf("body differs:\n new:      %s\n existing: %s", freshBody, againBody)
	}
	if sent := fx.sender.all(); len(sent) != 0 {
		t.Errorf("an existing account must get no mail from a sign-up attempt, got %d", len(sent))
	}

	postJSON(fx.srv, testOrgProject+"/verify-email", map[string]string{"token": link}).Body.Close()
	if login := fx.login(t, alicePassword); login.StatusCode != 200 {
		t.Errorf("original password after a repeat sign-up: got %d, want 200", login.StatusCode)
	}
}

// Without verification a sign-up signs the user in, so a taken address cannot
// be hidden; the answer stays a 409 with a message that names no account.
func TestIntegration_RegisterExistingEmailWithoutVerificationIsGeneric409(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()

	fx.register(t, aliceEmail).Body.Close()
	resp := fx.register(t, aliceEmail)
	var body map[string]interface{}
	decodeJSON(resp, &body)
	if resp.StatusCode != 409 || body["error"] != errCannotRegister.Error() {
		t.Errorf("got %d %v, want 409 %q", resp.StatusCode, body, errCannotRegister.Error())
	}
	if body["accessToken"] != nil {
		t.Error("a refused sign-up must not carry a session")
	}
}
