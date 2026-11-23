package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/store"
	"github.com/go-chi/chi/v5"
)

func TestIntegration_ClosedSignUpsNeverAskTheHook(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx := newHooksFixture(t, false)
	fx.useHooks(func(h *pool.AuthHooks) { h.BeforeUserCreated = fx.hook.url("/deny") })
	fx.settings.set(func(s *signInSettings) { s.allowNewUsers = false })
	resp, body := fx.call(http.MethodPost, oauthProject+"/register", "", map[string]string{
		"email": mailbox("closed-hook"), "password": oauthPassword, "fullName": "N"})
	if resp.StatusCode != http.StatusForbidden || body["error"] != codeSignupDisabled {
		t.Fatalf("got %d %v, want 403 signup_disabled", resp.StatusCode, body)
	}
	if calls := fx.hook.received("/deny"); len(calls) != 0 {
		t.Fatalf("a closed project sent %d sign-up attempts to its hook", len(calls))
	}
}

func TestIntegration_NoCopyOfSettingsAndAssurance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx := newFailClosedFixture(t)
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	routes := chi.NewRouteContext()
	routes.URLParams.Add("orgSlug", "test-org")
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routes))
	user := domain.UserInfo{ID: 1, Email: "a@b.co"}

	t.Run("a session below aal2 is refused", func(t *testing.T) {
		fx.neverRead()
		fx.controlPlaneDown()
		defer fx.settings.set(func(s *signInSettings) { s.infoDown = false })
		if _, err := fx.handler.signSession(request, "test-project", auth.Claims{Sub: "1"}, user, "refresh", store.RefreshSession{}); err == nil {
			t.Fatal("an aal1 session was signed without the project's settings")
		}
	})
	t.Run("an aal2 session keeps its level", func(t *testing.T) {
		fx.neverRead()
		fx.controlPlaneDown()
		defer fx.settings.set(func(s *signInSettings) { s.infoDown = false })
		session := store.RefreshSession{AAL: store.AAL2, AMR: []string{"password", "totp"}}
		resp, err := fx.handler.signSession(request, "test-project", auth.Claims{Sub: "1"}, user, "refresh", session)
		if err != nil {
			t.Fatalf("signSession: %v", err)
		}
		if claims := jwtPayload(t, resp.AccessToken); claims["aal"] != "aal2" {
			t.Fatalf("claims = %v", claims)
		}
	})
	t.Run("an api-key token keeps the default labels", func(t *testing.T) {
		fx.neverRead()
		fx.controlPlaneDown()
		defer fx.settings.set(func(s *signInSettings) { s.infoDown = false })
		resp, err := fx.handler.generateAPIKeyAuthResponse(request, "test-project", 7, "publishable")
		if err != nil {
			t.Fatalf("generateAPIKeyAuthResponse: %v", err)
		}
		if claims := jwtPayload(t, resp.AccessToken); claims["projectName"] != "test-project" || claims["orgSlug"] != "test-org" {
			t.Fatalf("claims = %v", claims)
		}
	})
}
