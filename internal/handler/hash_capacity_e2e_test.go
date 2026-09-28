package handler

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/excalibase/auth/internal/auth"
)

// switchableHasher answers busy while saturated and otherwise hashes for real.
type switchableHasher struct {
	real      *auth.Hasher
	saturated atomic.Bool
}

func (s *switchableHasher) Hash(ctx context.Context, password string) (string, error) {
	if s.saturated.Load() {
		return "", auth.ErrHashBusy
	}
	return s.real.Hash(ctx, password)
}

func (s *switchableHasher) Check(ctx context.Context, password, encoded string) (bool, error) {
	if s.saturated.Load() {
		return false, auth.ErrHashBusy
	}
	return s.real.Check(ctx, password, encoded)
}

func assertBusy(t *testing.T, resp *http.Response, what string) {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("%s while hashing is saturated: got %d, want 503", what, resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Errorf("%s: a busy refusal must say when to retry", what)
	}
}

func TestIntegration_SaturatedHashingRefusesRegisterWithoutCreatingTheUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()

	fx.hashes.saturated.Store(true)
	assertBusy(t, fx.register(t, aliceEmail), "register")

	var n int
	if err := fx.db.QueryRow(context.Background(), "SELECT count(*) FROM auth.users").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a refused registration left %d user rows", n)
	}
}

// Busy is not a wrong password: the caller must not be told 401, and the
// identity lock must not count it.
func TestIntegration_SaturatedHashingRefusesLoginAsBusy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()
	fx.register(t, aliceEmail).Body.Close()

	fx.hashes.saturated.Store(true)
	assertBusy(t, fx.login(t, alicePassword), "login")

	fx.hashes.saturated.Store(false)
	resp := fx.login(t, alicePassword)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login once capacity returns: got %d", resp.StatusCode)
	}
}

// A reset refused for capacity must leave the emailed link usable.
func TestIntegration_SaturatedHashingDoesNotBurnTheResetLink(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()
	fx.registerAndForget(t)
	fx.forgotPassword(t, aliceEmail).Body.Close()
	resetToken := resetLinkToken(t, fx.sender.last(t))
	body := map[string]string{"token": resetToken, "newPassword": newPassword}

	fx.hashes.saturated.Store(true)
	assertBusy(t, postJSON(fx.srv, testOrgProject+"/reset-password", body), "reset")

	fx.hashes.saturated.Store(false)
	resp := postJSON(fx.srv, testOrgProject+"/reset-password", body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the same link once capacity returns: got %d", resp.StatusCode)
	}
	login := fx.login(t, newPassword)
	login.Body.Close()
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login with the reset password: got %d", login.StatusCode)
	}
}

// Two redeems that both looked the link up before either consumed it: only
// the first claim may win.
func TestIntegration_AResetLinkLookedUpTwiceIsClaimedOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupVerifyFixture(t, false)
	defer cleanup()
	fx.registerAndForget(t)
	fx.forgotPassword(t, aliceEmail).Body.Close()
	resetToken := resetLinkToken(t, fx.sender.last(t))

	ctx := context.Background()
	rowID, _, err := passwordResetTokens.lookup(ctx, fx.db, resetToken)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if err := passwordResetTokens.claim(ctx, fx.db, rowID); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := passwordResetTokens.claim(ctx, fx.db, rowID); err == nil {
		t.Fatal("a consumed link was claimed a second time")
	}
}
