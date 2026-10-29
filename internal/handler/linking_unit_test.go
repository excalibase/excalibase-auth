package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/store"
)

func TestRecentlySignedInNeedsASignInTimeWithinTheWindow(t *testing.T) {
	now := time.Unix(time.Now().Unix(), 0)
	cases := map[string]struct {
		claims *auth.Claims
		want   bool
	}{
		"no token":            {nil, false},
		"no sign-in time":     {&auth.Claims{}, false},
		"just now":            {&auth.Claims{AuthTime: now.Unix()}, true},
		"at the window's end": {&auth.Claims{AuthTime: now.Add(-reauthWindow).Unix()}, true},
		"past the window":     {&auth.Claims{AuthTime: now.Add(-reauthWindow - time.Second).Unix()}, false},
		"far in the future":   {&auth.Claims{AuthTime: now.Add(time.Hour).Unix()}, false},
	}
	for name, tc := range cases {
		if got := recentlySignedIn(tc.claims, now); got != tc.want {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}

func TestLinkTicketsAndStatesHashApart(t *testing.T) {
	if linkTicketHash("same") == linkTicketHash("other") || linkTicketHash("same") == "same" {
		t.Fatal("ticket hashes collide")
	}
}

func TestWriteStoreFailureMapsTheStoreErrors(t *testing.T) {
	for err, want := range map[error]int{
		store.ErrNotFound:    http.StatusNotFound,
		store.ErrUnavailable: http.StatusServiceUnavailable,
		errInvalidGrant:      http.StatusInternalServerError,
	} {
		rec := httptest.NewRecorder()
		writeStoreFailure(rec, err, "missing")
		if rec.Code != want {
			t.Errorf("%v: %d, want %d", err, rec.Code, want)
		}
	}
}

func TestAGuestIsFreshByAFreshTokenAndNoOneElseIs(t *testing.T) {
	now := time.Now()
	old, recent := now.Add(-time.Hour).Unix(), now.Add(-time.Minute).Unix()
	for _, c := range []struct {
		name   string
		claims *auth.Claims
		guest  bool
		want   bool
	}{
		{"a recent sign-in", &auth.Claims{AuthTime: recent, IssuedAt: old}, false, true},
		{"a member's fresh token", &auth.Claims{AuthTime: old, IssuedAt: recent}, false, false},
		{"a guest's fresh token", &auth.Claims{AuthTime: old, IssuedAt: recent}, true, true},
		{"a guest's old token", &auth.Claims{AuthTime: old, IssuedAt: old}, true, false},
		{"a guest's token from the future", &auth.Claims{IssuedAt: now.Add(time.Hour).Unix()}, true, false},
		{"no token", nil, true, false},
	} {
		if got := freshEnough(c.claims, c.guest, now); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
