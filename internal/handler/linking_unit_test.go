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
