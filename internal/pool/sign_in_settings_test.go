package pool

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/token"
)

func TestSignInSettingsDecodeAndDefault(t *testing.T) {
	hits := 0
	srv := newInfoServer(t, `{"projectId":"p1","redirectUrls":["https://app.test/cb"],"allowNewUsers":false,
		"oauthProviders":[{"provider":"github","clientId":"gh-id","callbackUrl":"https://api.test/auth/o/p1/callback/github"}]}`, &hits)
	defer srv.Close()
	info, err := NewManager(srv.URL, token.Literal("pat"), time.Hour).GetProjectInfo(context.Background(), "p1")
	if err != nil {
		t.Fatal(err)
	}
	provider, ok := info.OAuthProvider("github")
	if !ok || provider.ClientID != "gh-id" || provider.CallbackURL != "https://api.test/auth/o/p1/callback/github" {
		t.Fatalf("github = %+v %v", provider, ok)
	}
	if _, ok := info.OAuthProvider("google"); ok {
		t.Fatal("a provider the project did not enable was found")
	}
	if info.NewUsersAllowed() || len(info.RedirectURLs) != 1 {
		t.Fatalf("info = %+v", info)
	}

	empty := ProjectInfo{}
	if !empty.NewUsersAllowed() || empty.OAuthEnabled() {
		t.Fatal("an older control plane must read as sign-ups open and no providers")
	}
}

func TestEmailSignInIsOnOnlyWhenTheControlPlaneSaysSo(t *testing.T) {
	hits := 0
	srv := newInfoServer(t, `{"projectId":"p1","emailOtpEnabled":true}`, &hits)
	defer srv.Close()
	info, err := NewManager(srv.URL, token.Literal("pat"), time.Hour).GetProjectInfo(context.Background(), "p1")
	if err != nil || !info.EmailOTPEnabled {
		t.Fatalf("info = %+v %v", info, err)
	}
	if (ProjectInfo{}).EmailOTPEnabled {
		t.Fatal("an older control plane must read as email sign-in off")
	}
}

func TestGetProjectInfoWithinRefetchesAnOlderCopy(t *testing.T) {
	hits := 0
	srv := newInfoServer(t, `{"projectId":"p1"}`, &hits)
	defer srv.Close()
	mgr := NewManager(srv.URL, token.Literal("pat"), time.Hour)
	ctx := context.Background()
	if _, err := mgr.GetProjectInfo(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.GetProjectInfoWithin(ctx, "p1", time.Hour); err != nil || hits != 1 {
		t.Fatalf("a fresh copy was refetched: hits=%d err=%v", hits, err)
	}
	if _, err := mgr.GetProjectInfoWithin(ctx, "p1", 0); err != nil || hits != 2 {
		t.Fatalf("a stale copy was served: hits=%d err=%v", hits, err)
	}
}

func TestGetProjectInfoWithinFailsClosed(t *testing.T) {
	up := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"projectId":"p1","oauthProviders":[{"provider":"github","clientId":"x","callbackUrl":"https://cb"}]}`))
	}))
	defer srv.Close()
	mgr := NewManager(srv.URL, token.Literal("pat"), time.Hour)
	if _, err := mgr.GetProjectInfoWithin(context.Background(), "p1", 0); err != nil {
		t.Fatal(err)
	}
	up = false
	if _, err := mgr.GetProjectInfoWithin(context.Background(), "p1", 0); err == nil {
		t.Fatal("an unreachable control plane served the old copy")
	}
}

func TestProviderSecretReadsTheProjectsVaultEntry(t *testing.T) {
	var path, auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth = r.URL.Path, r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/vault/secrets/projects/p1/auth/providers/github":
			_, _ = w.Write([]byte(`{"client_secret":"s3cret"}`))
		case "/vault/secrets/projects/p1/auth/providers/google":
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	mgr := NewManager(srv.URL, token.Literal("pat"), time.Hour)
	ctx := context.Background()
	secret, err := mgr.ProviderSecret(ctx, "p1", "github")
	if err != nil || secret != "s3cret" || path != "/vault/secrets/projects/p1/auth/providers/github" || auth != "Bearer pat" {
		t.Fatalf("secret=%q err=%v path=%s auth=%s", secret, err, path, auth)
	}
	if _, err := mgr.ProviderSecret(ctx, "p1", "google"); !errors.Is(err, ErrNoProviderSecret) {
		t.Fatalf("empty entry: %v", err)
	}
	if _, err := mgr.ProviderSecret(ctx, "p2", "github"); err == nil {
		t.Fatal("a refused read returned a secret")
	}
	if _, err := mgr.ProviderSecret(ctx, "p1", "../credentials"); err == nil {
		t.Fatal("a provider name outside the known set reached the vault")
	}
}

func TestAProviderWithoutAnAbsoluteCallbackIsOff(t *testing.T) {
	for _, callback := range []string{"/auth/o/p1/callback/github", "api.test/auth/o/p1/callback/github", "ftp://api.test/cb", "https:///cb"} {
		info := ProjectInfo{OAuthProviders: []OAuthProvider{{Provider: "github", ClientID: "gh-id", CallbackURL: callback}}}
		if _, ok := info.OAuthProvider("github"); ok || info.OAuthEnabled() {
			t.Fatalf("callback %q left the provider on", callback)
		}
	}
}

func TestCaptchaSecretReadsTheProjectsVaultEntry(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		switch r.URL.Path {
		case "/vault/secrets/projects/p1/auth/captcha":
			_, _ = w.Write([]byte(`{"secret_key":"ts-secret"}`))
		case "/vault/secrets/projects/p2/auth/captcha":
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	mgr := NewManager(srv.URL, token.Literal("pat"), time.Hour)
	ctx := context.Background()
	if secret, err := mgr.CaptchaSecret(ctx, "p1"); err != nil || secret != "ts-secret" || path != "/vault/secrets/projects/p1/auth/captcha" {
		t.Fatalf("secret=%q err=%v path=%s", secret, err, path)
	}
	if _, err := mgr.CaptchaSecret(ctx, "p2"); !errors.Is(err, ErrNoCaptchaSecret) {
		t.Fatalf("empty entry: %v", err)
	}
	if _, err := mgr.CaptchaSecret(ctx, "p3"); err == nil {
		t.Fatal("a refused read returned a secret")
	}
}

func TestGuestSwitchReadsAsOffWhileTheFlagIsOff(t *testing.T) {
	on, off := true, false
	for _, c := range []struct {
		info          ProjectInfo
		flag, enabled bool
	}{
		{ProjectInfo{}, false, false},
		{ProjectInfo{GuestSignInEnabled: &off}, true, false},
		{ProjectInfo{GuestSignInEnabled: &on}, true, true},
	} {
		if c.info.GuestsOn() != c.flag || c.info.GuestSignInOn() != c.enabled {
			t.Errorf("%+v: on=%v enabled=%v", c.info, c.info.GuestsOn(), c.info.GuestSignInOn())
		}
	}
}
