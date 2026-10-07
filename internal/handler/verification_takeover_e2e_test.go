package handler

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/email"
	"github.com/google/uuid"
)

const squatterPassword = "squatter-password-1"

func (f *verifyFixture) registerWith(t *testing.T, password, fullName string) *http.Response {
	t.Helper()
	return postJSON(f.srv, testOrgProject+"/register", map[string]string{
		"email": aliceEmail, "password": password, "fullName": fullName,
	})
}

func (f *verifyFixture) verify(t *testing.T, link string) (int, map[string]interface{}) {
	t.Helper()
	resp := postJSON(f.srv, testOrgProject+"/verify-email", map[string]string{"token": link})
	var body map[string]interface{}
	decodeJSON(resp, &body)
	return resp.StatusCode, body
}

func (f *verifyFixture) refresh(t *testing.T, refreshToken string) int {
	t.Helper()
	resp := postJSON(f.srv, testOrgProject+"/token", map[string]string{
		"grant_type": "refresh_token", "refresh_token": refreshToken,
	})
	resp.Body.Close()
	return resp.StatusCode
}

func (f *verifyFixture) aliceID(t *testing.T) int64 {
	t.Helper()
	var id int64
	if err := f.db.QueryRow(context.Background(), "SELECT id FROM auth.users WHERE email = $1", aliceEmail).Scan(&id); err != nil {
		t.Fatalf("read user id: %v", err)
	}
	return id
}

func (f *verifyFixture) mintRefreshToken(t *testing.T) string {
	t.Helper()
	plaintext, err := storeRefreshToken(context.Background(), f.db, f.aliceID(t),
		refreshSession{familyID: uuid.New(), expiry: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("mint refresh token: %v", err)
	}
	return plaintext
}

func loginStatus(t *testing.T, f *verifyFixture, password string) int {
	t.Helper()
	resp := f.login(t, password)
	resp.Body.Close()
	return resp.StatusCode
}

// The real owner signing up after a squatter replaces the squatter's password
// and name, gets a fresh link, and sees the answer a new address gets.
func TestIntegration_RegisterOverwritesAnUnverifiedSquatter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, true)
	defer cleanup()

	squat := fx.registerWith(t, squatterPassword, "Alice")
	squatBody := readBody(t, squat)
	squatterLink := verificationLinkToken(t, fx.sender.last(t))
	fx.sender.reset()

	owner := fx.registerWith(t, alicePassword, "Alice")
	if owner.StatusCode != squat.StatusCode || readBody(t, owner) != squatBody {
		t.Fatalf("overwrite must answer like a new sign-up: got %d", owner.StatusCode)
	}
	ownerLink := verificationLinkToken(t, fx.sender.last(t))

	if code, _ := fx.verify(t, squatterLink); code != 400 {
		t.Errorf("the squatter's link must be dead after the overwrite: got %d", code)
	}
	code, body := fx.verify(t, ownerLink)
	if code != 200 || body["passwordResetRequired"] != nil {
		t.Fatalf("owner's sign-up link: got %d %v, want 200 without a reset", code, body)
	}
	if got := loginStatus(t, fx, alicePassword); got != 200 {
		t.Errorf("owner login: got %d, want 200", got)
	}
	if got := loginStatus(t, fx, squatterPassword); got != 401 {
		t.Errorf("squatter login: got %d, want 401", got)
	}
}

// Overwrites share the resend budget; past it a sign-up changes nothing, so a
// spent budget can lock nobody out of a password they did not choose.
func TestIntegration_RegisterOverwriteIsThrottledAsANoOp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, true)
	defer cleanup()

	fx.registerWith(t, alicePassword, "Alice").Body.Close()
	for i := 0; i < resendVerificationLimit; i++ {
		fx.registerWith(t, alicePassword, "Alice").Body.Close()
	}
	link := verificationLinkToken(t, fx.sender.last(t))
	fx.sender.reset()

	over := fx.registerWith(t, squatterPassword, "Mallory")
	if over.StatusCode != 201 {
		t.Errorf("throttled sign-up must still answer like a new one: got %d", over.StatusCode)
	}
	over.Body.Close()
	if len(fx.sender.all()) != 0 {
		t.Error("a throttled sign-up must send nothing")
	}
	if code, _ := fx.verify(t, link); code != 200 {
		t.Fatalf("the latest link must survive a throttled sign-up: got %d", code)
	}
	if got := loginStatus(t, fx, alicePassword); got != 200 {
		t.Errorf("password after a throttled overwrite: got %d, want 200", got)
	}
}

// A resend link proves the address, not the stored password: redeeming it
// disables that password, ends every session, and mails a reset link.
func TestIntegration_ResendLinkRequiresANewPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()

	signup := fx.registerWith(t, squatterPassword, "Mallory")
	var session map[string]interface{}
	decodeJSON(signup, &session)
	squatterRefresh := session["refreshToken"].(string)

	postJSON(fx.srv, testOrgProject+"/resend-verification", map[string]string{"email": aliceEmail}).Body.Close()
	code, body := fx.verify(t, verificationLinkToken(t, fx.sender.last(t)))
	if code != 200 || body["verified"] != true || body["passwordResetRequired"] != true {
		t.Fatalf("resend link: got %d %v, want verified with passwordResetRequired", code, body)
	}
	if got := fx.refresh(t, squatterRefresh); got != 401 {
		t.Errorf("a session from before verification must be revoked: got %d", got)
	}
	if got := loginStatus(t, fx, squatterPassword); got != 401 {
		t.Errorf("the unproven password must stop working: got %d", got)
	}

	reset := fx.sender.last(t)
	if reset.Template != email.TemplatePasswordReset || reset.To != aliceEmail {
		t.Fatalf("expected a reset mail to the owner, got %q to %q", reset.Template, reset.To)
	}
	postJSON(fx.srv, testOrgProject+"/reset-password", map[string]string{
		"token": resetLinkToken(t, reset), "newPassword": newPassword,
	}).Body.Close()
	if got := loginStatus(t, fx, newPassword); got != 200 {
		t.Errorf("login with the owner's new password: got %d, want 200", got)
	}
	if !fx.emailVerified(t, aliceEmail) {
		t.Error("the account should be verified")
	}
}

// The first verification ends every session, even through a sign-up link.
func TestIntegration_FirstVerificationRevokesSessions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, true)
	defer cleanup()

	fx.register(t, aliceEmail).Body.Close()
	link := verificationLinkToken(t, fx.sender.last(t))
	earlier := fx.mintRefreshToken(t)

	if code, _ := fx.verify(t, link); code != 200 {
		t.Fatalf("verify: got %d", code)
	}
	if got := fx.refresh(t, earlier); got != 401 {
		t.Errorf("refresh with a pre-verification session: got %d, want 401", got)
	}
}

// On a project that requires verification an unverified account gets no
// session by password and cannot keep one alive by refresh.
func TestIntegration_UnverifiedAccountCannotSignInOrRefresh(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, true)
	defer cleanup()

	fx.register(t, aliceEmail).Body.Close()
	if got := loginStatus(t, fx, alicePassword); got != 403 {
		t.Errorf("password login while unverified: got %d, want 403", got)
	}
	if got := fx.refresh(t, fx.mintRefreshToken(t)); got != 403 {
		t.Errorf("refresh while unverified: got %d, want 403", got)
	}
}
