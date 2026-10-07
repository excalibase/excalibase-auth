package handler

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// A project with no usable site URL must never get a relative link (EXC-561).

func decodeBody(t *testing.T, resp io.Reader) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	json.NewDecoder(resp).Decode(&body)
	return body
}

func TestIntegration_ForgotPasswordRefusesWithoutSiteURL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixtureWithSite(t, false, "", "")
	defer cleanup()

	resp := fx.forgotPassword(t, aliceEmail)
	defer resp.Body.Close()
	if resp.StatusCode != 422 {
		t.Fatalf("forgot-password without a site URL: got %d, want 422", resp.StatusCode)
	}
	body := decodeBody(t, resp.Body)
	if body["code"] != "site_url_required" {
		t.Errorf("error code: got %v", body["code"])
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "site URL") {
		t.Errorf("error should tell the developer to set the site URL: %q", msg)
	}
	if n := len(fx.sender.all()); n != 0 {
		t.Fatalf("no mail may be sent, got %d", n)
	}
}

func TestIntegration_ForgotPasswordIgnoresAnUnusableProjectSiteURL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixtureWithSite(t, false, "/relative", "https://fallback.test")
	defer cleanup()
	fx.registerAndForget(t)

	resp := fx.forgotPassword(t, aliceEmail)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("forgot-password: got %d", resp.StatusCode)
	}
	if got := fx.sender.last(t).Data["resetUrl"]; !strings.HasPrefix(got, "https://fallback.test/reset-password?token=") {
		t.Errorf("reset url: got %q", got)
	}
}

func TestIntegration_RegisterRefusesWithoutSiteURLWhenVerificationRequired(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixtureWithSite(t, true, "", "")
	defer cleanup()

	resp := fx.register(t, aliceEmail)
	defer resp.Body.Close()
	if resp.StatusCode != 422 {
		t.Fatalf("register without a site URL: got %d, want 422", resp.StatusCode)
	}
	if code := decodeBody(t, resp.Body)["code"]; code != "site_url_required" {
		t.Errorf("error code: got %v", code)
	}
	var accounts int
	fx.db.QueryRow(context.Background(), "SELECT count(*) FROM auth.users").Scan(&accounts)
	if accounts != 0 {
		t.Errorf("a refused sign-up must not leave an account behind, got %d", accounts)
	}
	if n := len(fx.sender.all()); n != 0 {
		t.Fatalf("no mail may be sent, got %d", n)
	}
}

func TestIntegration_RegisterWithoutSiteURLStillWorksWhenVerificationIsOff(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixtureWithSite(t, false, "", "")
	defer cleanup()

	resp := fx.register(t, aliceEmail)
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("register: got %d", resp.StatusCode)
	}
}

func TestIntegration_ResendVerificationRefusesWithoutSiteURL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixtureWithSite(t, true, "", "")
	defer cleanup()

	resp := postJSON(fx.srv, testOrgProject+"/resend-verification", map[string]string{"email": aliceEmail})
	defer resp.Body.Close()
	if resp.StatusCode != 422 {
		t.Fatalf("resend without a site URL: got %d, want 422", resp.StatusCode)
	}
}
