package handler

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

// failClosedFixture is a project that requires verified addresses, holding one
// unverified and one verified password account.
type failClosedFixture struct {
	*otpFixture
	unverified, verified string
	unverifiedRefresh    string
	verifiedRefresh      string
}

func newFailClosedFixture(t *testing.T) *failClosedFixture {
	t.Helper()
	fx := newPostgresOTPFixture(t)
	// Registered while verification is off, so the account stays unverified.
	session, unverified := fx.passwordAccount(t, "fc-unverified")
	fx.settings.set(func(s *signInSettings) { s.requireVerification = true })
	_, verified := fx.passwordAccount(t, "fc-verified")
	link, err := url.Parse(fx.sender.last(t).Data["verifyUrl"])
	if err != nil {
		t.Fatal(err)
	}
	resp := postJSON(fx.srv, oauthProject+"/verify-email", map[string]string{"token": link.Query().Get("token")})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify: %d", resp.StatusCode)
	}
	resp.Body.Close()
	verifiedSession := tokenResponse(t, postJSON(fx.srv, oauthProject+"/login", map[string]string{"email": verified, "password": oauthPassword}), "verified login")
	return &failClosedFixture{otpFixture: fx, unverified: unverified, verified: verified,
		unverifiedRefresh: refreshTokenOf(session), verifiedRefresh: refreshTokenOf(verifiedSession)}
}

func (fx *failClosedFixture) login(address string) (*http.Response, map[string]any) {
	return fx.call(http.MethodPost, oauthProject+"/login", "", map[string]string{"email": address, "password": oauthPassword})
}

func (fx *failClosedFixture) controlPlaneDown() {
	fx.settings.set(func(s *signInSettings) { s.infoDown = true })
}

// neverRead leaves the service with no copy of the project's settings.
func (fx *failClosedFixture) neverRead() {
	fx.handler.poolMgr.ForgetProjectInfo("test-project")
}

// staleRequired leaves a copy past its TTL that says verification is required.
func (fx *failClosedFixture) staleRequired(t *testing.T) {
	t.Helper()
	if resp, body := fx.login(fx.unverified); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("priming read: %d %v", resp.StatusCode, body)
	}
	fx.handler.poolMgr.AgeProjectInfo("test-project", 3*time.Hour)
}

func TestIntegration_VerificationFailsClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx := newFailClosedFixture(t)

	t.Run("login, no copy of the settings", func(t *testing.T) {
		fx.neverRead()
		fx.controlPlaneDown()
		defer fx.settings.set(func(s *signInSettings) { s.infoDown = false })
		if resp, body := fx.login(fx.unverified); resp.StatusCode != http.StatusServiceUnavailable || body["error"] != errSettingsUnreadable {
			t.Fatalf("got %d %v, want 503", resp.StatusCode, body)
		}
	})
	t.Run("login, stale copy requiring verification", func(t *testing.T) {
		fx.staleRequired(t)
		fx.controlPlaneDown()
		defer fx.settings.set(func(s *signInSettings) { s.infoDown = false })
		if resp, body := fx.login(fx.unverified); resp.StatusCode != http.StatusForbidden || body["error"] != errEmailNotVerified.Error() {
			t.Fatalf("got %d %v, want 403 email not verified", resp.StatusCode, body)
		}
	})
	t.Run("refresh, no copy of the settings", func(t *testing.T) {
		fx.neverRead()
		fx.controlPlaneDown()
		defer fx.settings.set(func(s *signInSettings) { s.infoDown = false })
		if resp, body := fx.refreshWith(fx.unverifiedRefresh); resp.StatusCode != http.StatusServiceUnavailable || body["error"] != errSettingsUnreadable {
			t.Fatalf("got %d %v, want 503", resp.StatusCode, body)
		}
	})
	t.Run("refresh, stale copy requiring verification", func(t *testing.T) {
		fx.staleRequired(t)
		fx.controlPlaneDown()
		defer fx.settings.set(func(s *signInSettings) { s.infoDown = false })
		if resp, body := fx.refreshWith(fx.unverifiedRefresh); resp.StatusCode != http.StatusForbidden || body["error"] != errEmailNotVerified.Error() {
			t.Fatalf("got %d %v, want 403 email not verified", resp.StatusCode, body)
		}
	})
	t.Run("verified user, stale copy, control plane down", func(t *testing.T) {
		fx.staleRequired(t)
		fx.controlPlaneDown()
		defer fx.settings.set(func(s *signInSettings) { s.infoDown = false })
		if resp, body := fx.login(fx.verified); resp.StatusCode != http.StatusOK {
			t.Fatalf("login: %d %v", resp.StatusCode, body)
		}
	})
	t.Run("register, no copy of the settings", func(t *testing.T) {
		fx.neverRead()
		fx.controlPlaneDown()
		defer fx.settings.set(func(s *signInSettings) { s.infoDown = false })
		resp := postJSON(fx.srv, oauthProject+"/register", map[string]string{
			"email": mailbox("fc-new"), "password": oauthPassword, "fullName": "New"})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("got %d, want 503", resp.StatusCode)
		}
	})
}
