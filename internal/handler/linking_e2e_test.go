package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/email"
	"github.com/excalibase/auth/internal/oauth"
	"github.com/excalibase/auth/internal/testutil/idpfake"
)

func TestIntegration_IdentityLinkingOnPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	runLinkingFlows(t, newPostgresOTPFixture(t))
}

func TestIntegration_IdentityLinkingOnMySQL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	runLinkingFlows(t, newMySQLOTPFixture(t))
}

func runLinkingFlows(t *testing.T, fx *otpFixture) {
	t.Run("GitHubLinksToAGoogleAccountAndThenSignsInToIt", func(t *testing.T) { linkProviderThenSignIn(t, fx) })
	t.Run("AnIdentityOfAnotherAccountIsNotStolen", func(t *testing.T) { linkTakenIdentity(t, fx) })
	t.Run("TheLinkIsWrittenOnlyWithTheVerifierOfTheAppThatStartedIt", func(t *testing.T) { linkNeedsTheVerifier(t, fx) })
	t.Run("LinkingNeedsARecentSignInThatARefreshKeeps", func(t *testing.T) { linkNeedsFreshSignIn(t, fx) })
	t.Run("AnAccountWhoseAddressNobodyProvedLinksNothing", func(t *testing.T) { linkUnprovenAccount(t, fx) })
	t.Run("AnAddressProvenByCodeLinksAndThenSignsIn", func(t *testing.T) { linkAddressByCode(t, fx) })
	t.Run("UnlinkingKeepsAWayInAndIsAudited", func(t *testing.T) { unlinkKeepsAWayIn(t, fx) })
	t.Run("OnlyTheProjectsSignedInEndUsersReachTheRoutes", func(t *testing.T) { linkRoutesNeedAnEndUser(t, fx) })
	t.Run("OffOrUnreadableSettingsRefuseEveryRoute", func(t *testing.T) { linkFailsClosed(t, fx) })
	t.Run("ALinkStartIsCheckedBeforeAnythingIsSaved", func(t *testing.T) { linkStartRefusals(t, fx) })
	t.Run("AnAccountDisabledMidwayGetsNoLink", func(t *testing.T) { linkDisabledMidway(t, fx) })
	t.Run("AnAddressLinkRefusesNonASCIIAndAuditsTheAccountItReplaces", func(t *testing.T) { linkAddressRefusals(t, fx) })
}

const identitiesPath = oauthProject + "/user/identities"

func (fx *otpFixture) call(method, path, bearer string, body any) (*http.Response, map[string]any) {
	var payload bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&payload).Encode(body)
	}
	req, _ := http.NewRequest(method, fx.srv.URL+path, &payload)
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	var decoded map[string]any
	decodeJSON(resp, &decoded)
	return resp, decoded
}

func accessTokenOf(body map[string]any) string {
	token, _ := body["accessToken"].(string)
	return token
}

// startLink asks for a link ticket and returns it with the verifier the SDK keeps.
func (fx *otpFixture) startLink(t *testing.T, bearer, provider string) (string, string) {
	t.Helper()
	verifier := newVerifier(t)
	resp, body := fx.call(http.MethodPost, identitiesPath+"/authorize", bearer, map[string]string{
		"provider": provider, "redirect_to": appCallback,
		"code_challenge": oauth.S256(verifier), "code_challenge_method": "S256"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("start link: %d %v", resp.StatusCode, body)
	}
	ticket, _ := body["linkTicket"].(string)
	if ticket == "" {
		t.Fatalf("no ticket in %v", body)
	}
	return ticket, verifier
}

// browserLink walks /authorize with the ticket through the provider and back.
func (fx *otpFixture) browserLink(t *testing.T, ticket string, user idpfake.User) *url.URL {
	t.Helper()
	fx.idp.SignInAs(user)
	resp := get(t, fx.srv.URL+oauthProject+"/authorize?"+url.Values{"link_ticket": {ticket}}.Encode())
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize with ticket: %d", resp.StatusCode)
	}
	atProvider := get(t, resp.Header.Get("Location"))
	atProvider.Body.Close()
	callback := get(t, atProvider.Header.Get("Location"))
	callback.Body.Close()
	landed, err := url.Parse(callback.Header.Get("Location"))
	if err != nil || callback.StatusCode != http.StatusFound {
		t.Fatalf("callback: %d %v", callback.StatusCode, err)
	}
	return landed
}

func (fx *otpFixture) link(t *testing.T, bearer, provider string, user idpfake.User) (*http.Response, map[string]any) {
	t.Helper()
	ticket, verifier := fx.startLink(t, bearer, provider)
	landed := fx.browserLink(t, ticket, user)
	if landed.Query().Get("code") == "" {
		t.Fatalf("link landed at %s", landed)
	}
	return fx.exchange(landed.Query().Get("code"), verifier)
}

func (fx *otpFixture) identities(t *testing.T, bearer string) []map[string]any {
	t.Helper()
	resp, body := fx.call(http.MethodGet, identitiesPath, bearer, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list identities: %d %v", resp.StatusCode, body)
	}
	listed := []map[string]any{}
	raw, _ := body["identities"].([]any)
	for _, item := range raw {
		listed = append(listed, item.(map[string]any))
	}
	return listed
}

func providersOf(listed []map[string]any) []string {
	providers := []string{}
	for _, identity := range listed {
		providers = append(providers, fmt.Sprint(identity["provider"]))
	}
	return providers
}

func linkProviderThenSignIn(t *testing.T, fx *otpFixture) {
	owner := fx.signIn(t, "google", person("link-owner"))
	github := person("link-github")
	audits := fx.count(t, "audit_log")
	resp, linked := fx.link(t, accessTokenOf(owner), "github", github)
	if resp.StatusCode != http.StatusOK || userIDOf(linked) != userIDOf(owner) {
		t.Fatalf("link: %d %v, want a session for user %v", resp.StatusCode, linked, userIDOf(owner))
	}
	if claims := jwtPayload(t, accessTokenOf(linked)); claims["auth_time"] != nil {
		t.Fatalf("a link made the session look freshly signed in: %v", claims)
	}
	if resp, body := fx.call(http.MethodPost, identitiesPath+"/authorize", accessTokenOf(linked), map[string]string{
		"provider": "google", "redirect_to": appCallback, "code_challenge": oauth.S256(newVerifier(t)),
		"code_challenge_method": "S256"}); resp.StatusCode != http.StatusForbidden || body["error"] != codeReauthRequired {
		t.Fatalf("a second link from the linked session: %d %v", resp.StatusCode, body)
	}
	if got := fx.count(t, "audit_log"); got != audits+1 {
		t.Fatalf("a link wrote %d audit rows, want 1", got-audits)
	}
	if providers := providersOf(fx.identities(t, accessTokenOf(linked))); fmt.Sprint(providers) != "[google github]" {
		t.Fatalf("identities = %v", providers)
	}
	if again := fx.signIn(t, "github", github); userIDOf(again) != userIDOf(owner) {
		t.Fatalf("github signed in to %v, want %v", userIDOf(again), userIDOf(owner))
	}
}

func linkTakenIdentity(t *testing.T, fx *otpFixture) {
	taken := person("link-taken")
	holder := fx.signIn(t, "github", taken)
	other := fx.signIn(t, "google", person("link-thief"))
	resp, body := fx.link(t, accessTokenOf(other), "github", taken)
	if resp.StatusCode != http.StatusConflict || body["error"] != "identity_already_exists" {
		t.Fatalf("linking an identity of another account: %d %v", resp.StatusCode, body)
	}
	if again := fx.signIn(t, "github", taken); userIDOf(again) != userIDOf(holder) {
		t.Fatalf("the identity moved to %v, want %v", userIDOf(again), userIDOf(holder))
	}
}

func linkNeedsTheVerifier(t *testing.T, fx *otpFixture) {
	owner := fx.signIn(t, "google", person("link-verifier"))
	github := person("link-verifier-gh")
	ticket, _ := fx.startLink(t, accessTokenOf(owner), "github")
	landed := fx.browserLink(t, ticket, github)
	if resp, _ := fx.exchange(landed.Query().Get("code"), newVerifier(t)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("exchange with another verifier: %d", resp.StatusCode)
	}
	if providers := providersOf(fx.identities(t, accessTokenOf(owner))); len(providers) != 1 {
		t.Fatalf("a link was written without the verifier: %v", providers)
	}
	if resp := get(t, fx.srv.URL+oauthProject+"/authorize?link_ticket="+url.QueryEscape(ticket)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a ticket used twice: %d", resp.StatusCode)
	}
	if resp := get(t, fx.srv.URL+oauthProject+"/callback/github?state="+url.QueryEscape(ticket)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a ticket presented as a state: %d", resp.StatusCode)
	}
	fresh, _ := fx.startLink(t, accessTokenOf(owner), "github")
	forged := newBrowser()
	callback, _ := url.Parse(fx.srv.URL + oauthProject + "/callback/github")
	state := "link|" + fresh
	forged.Jar.SetCookies(callback, []*http.Cookie{{Name: stateCookieName(state), Value: state, Path: callback.Path}})
	if resp := getWith(t, forged, callback.String()+"?code=x&state="+url.QueryEscape(state)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a ticket forged into a state with its cookie: %d", resp.StatusCode)
	}
	if fresh := fx.signIn(t, "github", github); userIDOf(fresh) == userIDOf(owner) {
		t.Fatal("the identity reached the account without its link being redeemed")
	}
}

// staleToken is the access token of a sign-in made long enough ago.
func (fx *otpFixture) staleToken(t *testing.T, session map[string]any, signedIn time.Time) string {
	t.Helper()
	claims := jwtPayload(t, accessTokenOf(session))
	token, err := fx.jwtSvc.Sign(auth.Claims{
		Sub: fmt.Sprint(claims["sub"]), UserID: int64(userIDOf(session)), ProjectID: "test-project",
		Role: "user", AllowedRoles: []string{"user"}, Scope: "authenticated", EmailVerified: true, AuthTime: signedIn.Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func linkNeedsFreshSignIn(t *testing.T, fx *otpFixture) {
	session := fx.signIn(t, "google", person("link-stale"))
	stale := fx.staleToken(t, session, time.Now().Add(-10*time.Minute))
	unknown := fx.staleToken(t, session, time.Unix(0, 0))
	challenge := oauth.S256(newVerifier(t))
	for _, token := range []string{stale, unknown} {
		resp, body := fx.call(http.MethodPost, identitiesPath+"/authorize", token, map[string]string{
			"provider": "github", "redirect_to": appCallback, "code_challenge": challenge, "code_challenge_method": "S256"})
		if resp.StatusCode != http.StatusForbidden || body["error"] != "reauthentication_required" {
			t.Fatalf("link start with an old sign-in: %d %v", resp.StatusCode, body)
		}
		resp, body = fx.call(http.MethodPost, identitiesPath+"/email", token, map[string]string{
			"email": mailbox("stale"), "type": "email", "code_challenge": challenge, "code_challenge_method": "S256"})
		if resp.StatusCode != http.StatusForbidden || body["error"] != "reauthentication_required" {
			t.Fatalf("address link with an old sign-in: %d %v", resp.StatusCode, body)
		}
		if resp, body := fx.call(http.MethodDelete, identitiesPath+"/1", token, nil); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("unlink with an old sign-in: %d %v", resp.StatusCode, body)
		}
	}
	if listed := fx.identities(t, stale); len(listed) != 1 {
		t.Fatalf("listing needs no recent sign-in: %v", listed)
	}
	refreshed := tokenResponse(t, postJSON(fx.srv, oauthProject+"/token", map[string]string{
		"grant_type": "refresh_token", "refresh_token": session["refreshToken"].(string)}), "refresh")
	if jwtPayload(t, accessTokenOf(refreshed))["auth_time"] != jwtPayload(t, accessTokenOf(session))["auth_time"] {
		t.Fatal("a refresh moved the sign-in time")
	}
	fx.startLink(t, accessTokenOf(refreshed), "github")
}

func linkUnprovenAccount(t *testing.T, fx *otpFixture) {
	address := person("link-unproven").Email
	session := tokenResponse(t, postJSON(fx.srv, oauthProject+"/register", map[string]string{
		"email": address, "password": oauthPassword, "fullName": "Unproven"}), "register")
	for _, path := range []string{"/authorize", "/email"} {
		resp, body := fx.call(http.MethodPost, identitiesPath+path, accessTokenOf(session), map[string]string{
			"provider": "github", "email": mailbox("unproven"), "type": "email", "redirect_to": appCallback,
			"code_challenge": oauth.S256(newVerifier(t)), "code_challenge_method": "S256"})
		if resp.StatusCode != http.StatusForbidden || body["error"] != codeEmailUnverified {
			t.Fatalf("%s for an unproven account: %d %v", path, resp.StatusCode, body)
		}
	}
}

func linkAddressByCode(t *testing.T, fx *otpFixture) {
	owner := fx.signIn(t, "github", person("link-mail-owner"))
	address := mailbox("link-second")
	verifier := newVerifier(t)
	fx.sender.reset()
	resp, body := fx.call(http.MethodPost, identitiesPath+"/email", accessTokenOf(owner), map[string]string{
		"email": address, "type": "email", "code_challenge": oauth.S256(verifier), "code_challenge_method": "S256"})
	if resp.StatusCode != http.StatusOK || body["message"] != otpSentMessage {
		t.Fatalf("address link: %d %v", resp.StatusCode, body)
	}
	resp, linked := fx.verifyCode(address, fx.linkCode(t, address), verifier)
	if resp.StatusCode != http.StatusOK || userIDOf(linked) != userIDOf(owner) {
		t.Fatalf("verify the address: %d %v", resp.StatusCode, linked)
	}
	if providers := providersOf(fx.identities(t, accessTokenOf(owner))); fmt.Sprint(providers) != "[github email]" {
		t.Fatalf("identities = %v", providers)
	}
	otpWait(t, nil)
	if again := fx.signInWithCode(t, address); userIDOf(again) != userIDOf(owner) {
		t.Fatalf("the linked address signed in to %v, want %v", userIDOf(again), userIDOf(owner))
	}
	other := fx.signIn(t, "google", person("link-mail-other"))
	verifier = newVerifier(t)
	otpWait(t, nil)
	fx.call(http.MethodPost, identitiesPath+"/email", accessTokenOf(other), map[string]string{
		"email": address, "type": "email", "code_challenge": oauth.S256(verifier), "code_challenge_method": "S256"})
	if resp, body := fx.verifyCode(address, fx.linkCode(t, address), verifier); resp.StatusCode != http.StatusConflict || body["error"] != "identity_already_exists" {
		t.Fatalf("an address linked elsewhere: %d %v", resp.StatusCode, body)
	}
}

func unlinkKeepsAWayIn(t *testing.T, fx *otpFixture) {
	session := fx.signIn(t, "google", person("unlink"))
	bearer := accessTokenOf(session)
	only := fx.identities(t, bearer)[0]
	path := fmt.Sprintf("%s/%v", identitiesPath, only["id"])
	if resp, body := fx.call(http.MethodDelete, path, bearer, nil); resp.StatusCode != http.StatusConflict || body["error"] != "last_sign_in_method" {
		t.Fatalf("unlink the only way in: %d %v", resp.StatusCode, body)
	}
	if resp, _ := fx.link(t, bearer, "github", person("unlink-gh")); resp.StatusCode != http.StatusOK {
		t.Fatalf("link github: %d", resp.StatusCode)
	}
	audits := fx.count(t, "audit_log")
	if resp, body := fx.call(http.MethodDelete, path, bearer, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unlink google: %d %v", resp.StatusCode, body)
	}
	if got := fx.count(t, "audit_log"); got != audits+1 {
		t.Fatalf("an unlink wrote %d audit rows, want 1", got-audits)
	}
	if providers := providersOf(fx.identities(t, bearer)); fmt.Sprint(providers) != "[github]" {
		t.Fatalf("identities = %v", providers)
	}
	stranger := fx.signIn(t, "google", person("unlink-stranger"))
	theirs := fmt.Sprintf("%s/%v", identitiesPath, fx.identities(t, bearer)[0]["id"])
	if resp, _ := fx.call(http.MethodDelete, theirs, accessTokenOf(stranger), nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unlink another account's identity: %d", resp.StatusCode)
	}
}

func linkRoutesNeedAnEndUser(t *testing.T, fx *otpFixture) {
	session := fx.signIn(t, "google", person("link-callers"))
	anon, _ := fx.jwtSvc.Sign(auth.Claims{Sub: "apikey:1", ProjectID: "test-project", Role: auth.RoleAnon,
		AllowedRoles: []string{auth.RoleAnon}, Scope: "public", KeyID: 1})
	claims := jwtPayload(t, accessTokenOf(session))
	elsewhere, _ := fx.jwtSvc.Sign(auth.Claims{Sub: fmt.Sprint(claims["sub"]), UserID: int64(userIDOf(session)),
		ProjectID: "other-project", Role: "user", AllowedRoles: []string{"user"}, Scope: "authenticated", AuthTime: time.Now().Unix()})
	for name, bearer := range map[string]string{"no token": "", "an api key": anon, "another project": elsewhere, "garbage": "x.y.z"} {
		resp, body := fx.call(http.MethodGet, identitiesPath, bearer, nil)
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s listed identities: %d %v", name, resp.StatusCode, body)
		}
	}
}

func linkFailsClosed(t *testing.T, fx *otpFixture) {
	bearer := accessTokenOf(fx.signIn(t, "google", person("link-off")))
	fx.settings.set(func(s *signInSettings) { s.providers, s.emailOTP = nil, false })
	resp, body := fx.call(http.MethodGet, identitiesPath, bearer, nil)
	if resp.StatusCode != http.StatusNotFound || body["error"] != codeMethodOff {
		t.Fatalf("listing with sign-in methods off: %d %v", resp.StatusCode, body)
	}
	fx.settings.set(func(s *signInSettings) { s.providers, s.emailOTP = []string{"google", "github"}, true })
	resp, body = fx.call(http.MethodPost, identitiesPath+"/email", bearer, map[string]string{"email": mailbox("off"), "type": "email",
		"code_challenge": oauth.S256(newVerifier(t)), "code_challenge_method": "S256"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("address link with codes on: %d %v", resp.StatusCode, body)
	}
	fx.settings.set(func(s *signInSettings) { s.infoDown = true })
	defer fx.settings.set(func(s *signInSettings) { s.infoDown = false })
	for _, call := range []struct{ method, path string }{
		{http.MethodGet, identitiesPath}, {http.MethodPost, identitiesPath + "/authorize"},
		{http.MethodPost, identitiesPath + "/email"}, {http.MethodDelete, identitiesPath + "/1"},
	} {
		resp, body := fx.call(call.method, call.path, bearer, map[string]string{"provider": "github", "email": mailbox("off"),
			"type": "email", "redirect_to": appCallback, "code_challenge": oauth.S256(newVerifier(t)), "code_challenge_method": "S256"})
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("%s %s with settings unreadable: %d %v", call.method, call.path, resp.StatusCode, body)
		}
	}
	if resp := get(t, fx.srv.URL+oauthProject+"/authorize?link_ticket=anything"); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("authorize with a ticket and settings unreadable: %d", resp.StatusCode)
	}
}

func linkStartRefusals(t *testing.T, fx *otpFixture) {
	bearer := accessTokenOf(fx.signIn(t, "google", person("link-refusals")))
	challenge := oauth.S256(newVerifier(t))
	flows := fx.count(t, "flow_states")
	cases := []struct {
		body       map[string]string
		wantStatus int
	}{
		{map[string]string{"provider": "gitlab", "redirect_to": appCallback, "code_challenge": challenge, "code_challenge_method": "S256"}, http.StatusNotFound},
		{map[string]string{"provider": "github", "redirect_to": "https://evil.test/cb", "code_challenge": challenge, "code_challenge_method": "S256"}, http.StatusBadRequest},
		{map[string]string{"provider": "github", "redirect_to": appCallback, "code_challenge": challenge, "code_challenge_method": "plain"}, http.StatusBadRequest},
		{map[string]string{"provider": "github", "redirect_to": appCallback, "code_challenge": "short", "code_challenge_method": "S256"}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		if resp, body := fx.call(http.MethodPost, identitiesPath+"/authorize", bearer, tc.body); resp.StatusCode != tc.wantStatus {
			t.Errorf("%v: %d %v, want %d", tc.body, resp.StatusCode, body, tc.wantStatus)
		}
	}
	if resp, _ := fx.call(http.MethodPost, identitiesPath+"/authorize", bearer, "not an object"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a malformed body: %d", resp.StatusCode)
	}
	if fx.count(t, "flow_states") != flows {
		t.Fatal("a refused link start saved a ticket")
	}
	if resp, _ := fx.call(http.MethodDelete, identitiesPath+"/not-a-number", bearer, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unlink of a malformed id: %d", resp.StatusCode)
	}
}

func linkDisabledMidway(t *testing.T, fx *otpFixture) {
	user := person("link-disabled")
	session := fx.signIn(t, "google", user)
	ticket, verifier := fx.startLink(t, accessTokenOf(session), "github")
	landed := fx.browserLink(t, ticket, person("link-disabled-gh"))
	fx.disable(t, user.Email)
	if resp, body := fx.exchange(landed.Query().Get("code"), verifier); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("link to a disabled account: %d %v", resp.StatusCode, body)
	}
}

// linkCode is the code of the address-link mail, which says it adds an address.
func (fx *otpFixture) linkCode(t *testing.T, address string) string {
	t.Helper()
	msg := fx.sender.last(t)
	if msg.Template != email.TemplateLinkEmailOTP || msg.To != address {
		t.Fatalf("mail = %s to %s", msg.Template, msg.To)
	}
	return msg.Data["code"]
}

func linkAddressRefusals(t *testing.T, fx *otpFixture) {
	owner := accessTokenOf(fx.signIn(t, "google", person("link-mail-refusals")))
	resp, body := fx.call(http.MethodPost, identitiesPath+"/email", owner, map[string]string{
		"email": "\u212Aate@otp.test", "type": "email", "code_challenge": oauth.S256(newVerifier(t)), "code_challenge_method": "S256"})
	if resp.StatusCode != http.StatusBadRequest || body["error"] != codeInvalidEmail {
		t.Fatalf("a non-ASCII address: %d %v", resp.StatusCode, body)
	}
	squatted := mailbox("link-squatted")
	tokenResponse(t, postJSON(fx.srv, oauthProject+"/register", map[string]string{
		"email": squatted, "password": oauthPassword, "fullName": "Squatter"}), "register")
	audits := fx.count(t, "audit_log")
	verifier := newVerifier(t)
	fx.call(http.MethodPost, identitiesPath+"/email", owner, map[string]string{
		"email": squatted, "type": "email", "code_challenge": oauth.S256(verifier), "code_challenge_method": "S256"})
	if resp, body := fx.verifyCode(squatted, fx.linkCode(t, squatted), verifier); resp.StatusCode != http.StatusOK {
		t.Fatalf("link over a squatter: %d %v", resp.StatusCode, body)
	}
	if got := fx.count(t, "audit_log"); got != audits+2 {
		t.Fatalf("a link that replaced an account wrote %d audit rows, want 2", got-audits)
	}
	if resp := postJSON(fx.srv, oauthProject+"/login", map[string]string{"email": squatted, "password": oauthPassword}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the squatter still signs in: %d", resp.StatusCode)
	}
}
