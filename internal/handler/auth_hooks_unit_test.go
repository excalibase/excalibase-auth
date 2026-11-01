package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/hooks"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/store"
	"github.com/excalibase/auth/internal/token"
)

func TestSessionFailure_MapsHookOutcomes(t *testing.T) {
	cases := []struct {
		err    error
		status int
		want   error
	}{
		{fmt.Errorf("wrapped: %w", errHookFailed), http.StatusServiceUnavailable, errHookFailed},
		{errSignupDenied, http.StatusForbidden, errSignupDenied},
		{errors.New("sign failed"), http.StatusInternalServerError, errTokenGeneration},
	}
	for _, tc := range cases {
		status, got := sessionFailure(tc.err)
		if status != tc.status || got != tc.want {
			t.Errorf("sessionFailure(%v) = %d %v", tc.err, status, got)
		}
	}
	if hookRefusalCode(errSignupDenied) != codeSignupDenied || hookRefusalCode(errHookFailed) != codeHookFailed {
		t.Fatal("provider callback codes")
	}
}

func TestFailureReason_IsTheHooksOwnReasonOnly(t *testing.T) {
	if got := failureReason(&hooks.Failure{Reason: "the hook answered 500"}); got != "the hook answered 500" {
		t.Fatalf("reason = %q", got)
	}
	if got := failureReason(errors.New("dial tcp 10.0.0.1:443: refused")); got != "the call failed" {
		t.Fatalf("reason = %q", got)
	}
}

// Without a hook client a project with hooks on fails closed.
func TestCallHook_WithoutAClientFailsClosed(t *testing.T) {
	h := NewAuthHandler(pool.NewManager("http://127.0.0.1:1", token.Literal("pat"), time.Hour), nil, 0)
	err := h.callHook(context.Background(), "p1", hookCustomAccessToken, "https://hooks.example.com", 0, struct{}{}, nil)
	if !errors.Is(err, errHookFailed) {
		t.Fatalf("err = %v", err)
	}
}

func TestSameAccount_AnyChangeTheTokenCarriesCounts(t *testing.T) {
	base := store.Account{ID: 1, Role: "user", AllowedRoles: []string{"user"}, Email: "a@example.com", EmailVerified: true, Enabled: true}
	if !sameAccount(base, base) {
		t.Fatal("an unchanged account differs")
	}
	changes := map[string]func(*store.Account){
		"role":     func(a *store.Account) { a.Role = "editor" },
		"allowed":  func(a *store.Account) { a.AllowedRoles = []string{"user", "editor"} },
		"email":    func(a *store.Account) { a.Email = "b@example.com" },
		"verified": func(a *store.Account) { a.EmailVerified = false },
		"guest":    func(a *store.Account) { a.IsGuest = true },
		"enabled":  func(a *store.Account) { a.Enabled = false },
		"id":       func(a *store.Account) { a.ID = 2 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := base
			changed.AllowedRoles = append([]string(nil), base.AllowedRoles...)
			change(&changed)
			if sameAccount(base, changed) {
				t.Fatal("the change went unseen")
			}
		})
	}
}
