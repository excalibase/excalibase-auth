package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/excalibase/auth/internal/oauth"
	"github.com/excalibase/auth/internal/testutil/idpfake"
)

func TestIntegration_OAuthSignInOnPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	runOAuthFlows(t, newPostgresOAuthFixture(t))
}

func TestIntegration_OAuthSignInOnMySQL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	runOAuthFlows(t, newMySQLOAuthFixture(t))
}

var oauthSeq atomic.Int64

func person(name string) idpfake.User {
	n := oauthSeq.Add(1)
	return idpfake.User{Subject: fmt.Sprint(1000 + n), Email: fmt.Sprintf("%s-%d@oauth.test", name, n), EmailVerified: true, Name: "Name " + name}
}

func runOAuthFlows(t *testing.T, fx *oauthFixture) {
	t.Run("GitHubSignsUpThenSignsInToTheSameAccount", func(t *testing.T) { oauthSignUpThenIn(t, fx, "github") })
	t.Run("GoogleSignsUpThenSignsInToTheSameAccount", func(t *testing.T) { oauthSignUpThenIn(t, fx, "google") })
	t.Run("AnUnverifiedAccountIsTakenOverByTheInboxOwner", func(t *testing.T) { oauthTakeover(t, fx) })
	t.Run("AVerifiedAccountIsLinkedAndKeepsItsPassword", func(t *testing.T) { oauthLinksVerified(t, fx) })
	t.Run("AnAddressTheProviderDidNotVerifyIsRefused", func(t *testing.T) { oauthUnverifiedAtProvider(t, fx) })
	t.Run("ClosedSignUpsRefuseNewAccountsOnly", func(t *testing.T) { oauthSignUpsClosed(t, fx) })
	t.Run("AuthorizeRefusesBeforeTheProvider", func(t *testing.T) { oauthAuthorizeRefusals(t, fx) })
	t.Run("TheStateAndTheCodeAreSpentOnce", func(t *testing.T) { oauthSingleUse(t, fx) })
	t.Run("ProviderErrorsReachTheAppAsCodesOnly", func(t *testing.T) { oauthProviderErrors(t, fx) })
	t.Run("SettingsThatCannotBeReadFailClosed", func(t *testing.T) { oauthFailsClosed(t, fx) })
}

func oauthSignUpThenIn(t *testing.T, fx *oauthFixture, provider string) {
	user := person(provider)
	first := fx.signIn(t, provider, user)
	claims := jwtPayload(t, first["accessToken"].(string))
	if claims["sub"] != user.Email || claims["email_verified"] != true || claims["role"] != "user" || claims["scope"] != "authenticated" {
		t.Fatalf("claims = %v", claims)
	}
	if first["refreshToken"] == "" || userIDOf(first) <= 0 {
		t.Fatalf("session = %v", first)
	}
	again := fx.signIn(t, provider, user)
	if userIDOf(again) != userIDOf(first) {
		t.Fatalf("second sign-in reached user %v, want %v", userIDOf(again), userIDOf(first))
	}
	if !fx.passwordIsNull(t, user.Email) {
		t.Fatal("a provider-made account got a password")
	}
	if resp := postJSON(fx.srv, oauthProject+"/login", map[string]string{"email": user.Email, "password": ""}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("password sign-in to an account without a password: %d", resp.StatusCode)
	}
}

func oauthTakeover(t *testing.T, fx *oauthFixture) {
	victim := person("victim")
	// The squatter registers the victim's address first; nobody verified it.
	squatter := tokenResponse(t, postJSON(fx.srv, oauthProject+"/register", map[string]string{
		"email": victim.Email, "password": squatterPassword, "fullName": "Squatter"}), "register")
	owner := fx.signIn(t, "github", victim)
	if userIDOf(owner) != userIDOf(squatter) {
		t.Fatalf("takeover reached user %v, want the squatted account %v", userIDOf(owner), userIDOf(squatter))
	}
	if resp := postJSON(fx.srv, oauthProject+"/login", map[string]string{"email": victim.Email, "password": squatterPassword}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the squatter's password still signs in: %d", resp.StatusCode)
	}
	refresh := postJSON(fx.srv, oauthProject+"/token", map[string]string{"grant_type": "refresh_token", "refresh_token": squatter["refreshToken"].(string)})
	if refresh.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the squatter's session survived: %d", refresh.StatusCode)
	}
	if !fx.passwordIsNull(t, victim.Email) {
		t.Fatal("the squatter's password was kept")
	}
}

func oauthLinksVerified(t *testing.T, fx *oauthFixture) {
	user := person("linked")
	first := fx.signIn(t, "google", user)
	// The account now has a provider-verified address; a second provider links to it.
	other := user
	other.Subject = user.Subject + "0"
	second := fx.signIn(t, "github", other)
	if userIDOf(second) != userIDOf(first) {
		t.Fatalf("github reached user %v, want %v", userIDOf(second), userIDOf(first))
	}
}

func oauthUnverifiedAtProvider(t *testing.T, fx *oauthFixture) {
	user := person("unproven")
	user.EmailVerified = false
	for _, provider := range []string{"github", "google"} {
		landed, _ := fx.browserSignIn(t, provider, user)
		if landed.Query().Get("error") != "email_not_verified" || landed.Query().Get("code") != "" {
			t.Fatalf("%s landed at %s", provider, landed)
		}
	}
}

func oauthSignUpsClosed(t *testing.T, fx *oauthFixture) {
	known := person("known")
	fx.signIn(t, "github", known)
	fx.settings.set(func(s *signInSettings) { s.allowNewUsers = false })
	defer fx.settings.set(func(s *signInSettings) { s.allowNewUsers = true })

	landed, _ := fx.browserSignIn(t, "github", person("stranger"))
	if landed.Query().Get("error") != "signup_disabled" {
		t.Fatalf("a new account was let in: %s", landed)
	}
	fx.signIn(t, "github", known)
	if resp := postJSON(fx.srv, oauthProject+"/register", map[string]string{
		"email": person("pw").Email, "password": oauthPassword, "fullName": "Closed"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("password sign-up while sign-ups are closed: %d", resp.StatusCode)
	}
}

func oauthAuthorizeRefusals(t *testing.T, fx *oauthFixture) {
	challenge := oauth.S256("a-verifier-that-is-long-enough-to-be-valid-for-pkce")
	for name, tc := range map[string]struct {
		raw    string
		status int
	}{
		"redirect not on the list":  {fx.authorizeURL("github", "https://evil.test/cb", challenge), http.StatusBadRequest},
		"lookalike redirect":        {fx.authorizeURL("github", appCallback+"/../../evil", challenge), http.StatusBadRequest},
		"no challenge":              {fx.authorizeURL("github", appCallback, ""), http.StatusBadRequest},
		"plain challenge method":    {fx.srv.URL + oauthProject + "/authorize?provider=github&redirect_to=" + url.QueryEscape(appCallback) + "&code_challenge=" + challenge + "&code_challenge_method=plain", http.StatusBadRequest},
		"unknown provider":          {fx.authorizeURL("facebook", appCallback, challenge), http.StatusNotFound},
		"site URL is always listed": {fx.authorizeURL("github", "https://app.test", challenge), http.StatusFound},
	} {
		resp := get(t, tc.raw)
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Errorf("%s: %d, want %d", name, resp.StatusCode, tc.status)
		}
	}
	fx.settings.set(func(s *signInSettings) { s.providers = []string{"google"} })
	defer fx.settings.set(func(s *signInSettings) { s.providers = []string{"google", "github"} })
	resp := get(t, fx.authorizeURL("github", appCallback, challenge))
	var body map[string]any
	decodeJSON(resp, &body)
	if resp.StatusCode != http.StatusNotFound || body["error"] != "method_not_enabled" {
		t.Fatalf("a provider the project switched off: %d %v", resp.StatusCode, body)
	}
}

func oauthSingleUse(t *testing.T, fx *oauthFixture) {
	user := person("once")
	fx.idp.SignInAs(user)
	flow, _ := oauth.NewFlow()
	resp := get(t, fx.authorizeURL("github", appCallback, oauth.S256(flow.Verifier)))
	atProvider := get(t, resp.Header.Get("Location"))
	callback := atProvider.Header.Get("Location")
	if first := get(t, callback); first.StatusCode != http.StatusFound {
		t.Fatalf("first callback: %d", first.StatusCode)
	}
	if replay := get(t, callback); replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("a replayed state was accepted: %d", replay.StatusCode)
	}

	// A sign-in the attacker started cannot finish in another browser.
	attacker := newBrowser()
	started := getWith(t, attacker, fx.authorizeURL("github", appCallback, oauth.S256(flow.Verifier)))
	victimAtProvider := get(t, started.Header.Get("Location"))
	if planted := get(t, victimAtProvider.Header.Get("Location")); planted.StatusCode != http.StatusBadRequest {
		t.Fatalf("a sign-in started in another browser finished: %d", planted.StatusCode)
	}

	landed, verifier := fx.browserSignIn(t, "github", user)
	code := landed.Query().Get("code")
	other, _ := oauth.NewFlow()
	if resp, _ := fx.exchange(code, other.Verifier); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a wrong verifier: %d", resp.StatusCode)
	}
	if resp, _ := fx.exchange(code, verifier); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a code tried with a wrong verifier stayed usable: %d", resp.StatusCode)
	}
	landed, verifier = fx.browserSignIn(t, "github", user)
	if resp, _ := fx.exchange(landed.Query().Get("code"), verifier); resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange: %d", resp.StatusCode)
	}
	if resp, _ := fx.exchange(landed.Query().Get("code"), verifier); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a spent code was accepted: %d", resp.StatusCode)
	}
}

func oauthProviderErrors(t *testing.T, fx *oauthFixture) {
	flow, _ := oauth.NewFlow()
	resp := get(t, fx.authorizeURL("github", appCallback, oauth.S256(flow.Verifier)))
	atProvider, _ := url.Parse(resp.Header.Get("Location"))
	state := atProvider.Query().Get("state")
	denied := get(t, fx.srv.URL+oauthProject+"/callback/github?error=access_denied&error_description=%3Cscript%3E&state="+url.QueryEscape(state))
	landed, _ := url.Parse(denied.Header.Get("Location"))
	if denied.StatusCode != http.StatusFound || landed.Query().Get("error") != "access_denied" || len(landed.Query()) != 1 {
		t.Fatalf("denied: %d %s", denied.StatusCode, landed)
	}
	if denied.Header.Get("Referrer-Policy") != "no-referrer" || denied.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("headers = %v", denied.Header)
	}

	fx.settings.set(func(s *signInSettings) { s.secretMissing = true })
	defer fx.settings.set(func(s *signInSettings) { s.secretMissing = false })
	missing, _ := fx.browserSignIn(t, "github", person("nosecret"))
	if missing.Query().Get("error") != "temporarily_unavailable" {
		t.Fatalf("missing secret landed at %s", missing)
	}
}

func oauthFailsClosed(t *testing.T, fx *oauthFixture) {
	landed, verifier := fx.browserSignIn(t, "github", person("closed"))
	fx.settings.set(func(s *signInSettings) { s.infoDown = true })
	defer fx.settings.set(func(s *signInSettings) { s.infoDown = false })
	challenge := oauth.S256(verifier)
	if resp := get(t, fx.authorizeURL("github", appCallback, challenge)); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("authorize with settings unreadable: %d", resp.StatusCode)
	}
	if resp, _ := fx.exchange(landed.Query().Get("code"), verifier); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("exchange with settings unreadable: %d", resp.StatusCode)
	}
	fx.settings.set(func(s *signInSettings) { s.infoDown = false; s.providers = nil })
	defer fx.settings.set(func(s *signInSettings) { s.providers = []string{"google", "github"} })
	resp, body := fx.exchange(landed.Query().Get("code"), verifier)
	if resp.StatusCode != http.StatusBadRequest || body["error"] != errUnsupportedGrant.Error() {
		t.Fatalf("pkce with sign-in off must read as today's unknown grant: %d %v", resp.StatusCode, body)
	}
}
