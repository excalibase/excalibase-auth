package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// With no copy of the project's settings at all, nothing that reads them may
// carry on with defaults: the hooks, the stable subject and the assurance
// claims all come from there.
func TestIntegration_NoCopyOfSettingsFailsClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx := newFailClosedFixture(t)

	t.Run("a verified login is refused", func(t *testing.T) {
		fx.neverRead()
		fx.controlPlaneDown()
		defer fx.settings.set(func(s *signInSettings) { s.infoDown = false })
		if resp, body := fx.login(fx.verified); resp.StatusCode != http.StatusServiceUnavailable || body["error"] != errSettingsUnreadable {
			t.Fatalf("got %d %v, want 503", resp.StatusCode, body)
		}
	})
	t.Run("a verified refresh is refused and the token survives", func(t *testing.T) {
		fx.neverRead()
		fx.controlPlaneDown()
		if resp, body := fx.refreshWith(fx.verifiedRefresh); resp.StatusCode != http.StatusServiceUnavailable || body["error"] != errSettingsUnreadable {
			t.Fatalf("got %d %v, want 503", resp.StatusCode, body)
		}
		fx.settings.set(func(s *signInSettings) { s.infoDown = false })
		if resp, body := fx.refreshWith(fx.verifiedRefresh); resp.StatusCode != http.StatusOK {
			t.Fatalf("after recovery: %d %v", resp.StatusCode, body)
		}
	})
	t.Run("the sign-up switch is unreadable", func(t *testing.T) {
		fx.neverRead()
		fx.controlPlaneDown()
		defer fx.settings.set(func(s *signInSettings) { s.infoDown = false })
		if open, err := fx.handler.signupsOpen(t.Context(), "test-project"); err == nil || open {
			t.Fatalf("signupsOpen = %v, %v; want closed with an error", open, err)
		}
	})
	t.Run("the hooks are unreadable", func(t *testing.T) {
		fx.neverRead()
		fx.controlPlaneDown()
		defer fx.settings.set(func(s *signInSettings) { s.infoDown = false })
		if _, err := fx.handler.hookSettings(t.Context(), "test-project"); err == nil {
			t.Fatal("hookSettings had no error without a copy")
		}
	})
	t.Run("the labels are unreadable", func(t *testing.T) {
		fx.neverRead()
		fx.controlPlaneDown()
		defer fx.settings.set(func(s *signInSettings) { s.infoDown = false })
		request := httptest.NewRequest(http.MethodPost, oauthProject+"/login", nil)
		if _, err := fx.handler.labelsFor(request, "test-project"); err == nil {
			t.Fatal("labelsFor had no error without a copy")
		}
	})
	t.Run("a stale copy still signs a verified user in", func(t *testing.T) {
		fx.staleRequired(t)
		fx.controlPlaneDown()
		defer fx.settings.set(func(s *signInSettings) { s.infoDown = false })
		if resp, body := fx.login(fx.verified); resp.StatusCode != http.StatusOK {
			t.Fatalf("login: %d %v", resp.StatusCode, body)
		}
	})
}
