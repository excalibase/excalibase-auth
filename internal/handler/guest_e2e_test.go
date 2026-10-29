package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/email"
	"github.com/excalibase/auth/internal/store"
)

const (
	guestPath       = oauthProject + "/guest"
	turnstileSecret = "turnstile-secret"
	turnstilePass   = "turnstile-pass"
)

// fakeTurnstile accepts only turnstilePass under turnstileSecret; down answers 503.
func fakeTurnstile(t *testing.T, down *bool) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *down {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = r.ParseForm()
		ok := r.PostForm.Get("secret") == turnstileSecret && r.PostForm.Get("response") == turnstilePass
		writeJSON(w, map[string]any{"success": ok})
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func withGuests(turnstileURL string) func(*AuthHandler) {
	return func(h *AuthHandler) {
		h.captchaVerifyURL = turnstileURL
		h.guestLimits = store.GuestLimits{PerClientHour: 1000, PerProjectDay: 100000}
	}
}

func guestFixtures(t *testing.T, mysql bool) (*otpFixture, *bool) {
	down := new(bool)
	tune := withGuests(fakeTurnstile(t, down))
	var fx *otpFixture
	if mysql {
		fx = newMySQLOTPFixture(t, tune)
	} else {
		fx = newPostgresOTPFixture(t, tune)
	}
	on := true
	fx.settings.set(func(s *signInSettings) { s.guests, s.stableSubject = &on, true })
	return fx, down
}

func TestIntegration_GuestAccountsOnPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, down := guestFixtures(t, false)
	runGuestFlows(t, fx, down)
}

func TestIntegration_GuestAccountsOnMySQL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, down := guestFixtures(t, true)
	runGuestFlows(t, fx, down)
}

func runGuestFlows(t *testing.T, fx *otpFixture, turnstileDown *bool) {
	t.Run("AGuestSignsInWithNoAddressAndTheGuestRole", func(t *testing.T) { guestSignsIn(t, fx) })
	t.Run("AGuestRefreshesKeepingItsID", func(t *testing.T) { guestRefreshes(t, fx) })
	t.Run("OffOrUnreadableSettingsRefuseGuestSignIn", func(t *testing.T) { guestFailsClosed(t, fx) })
	t.Run("GuestSessionsEndWithTheFlagNotTheProjectSwitch", func(t *testing.T) { guestRefreshAfterSwitchOff(t, fx) })
	t.Run("GuestSignUpsAreCappedPerClient", func(t *testing.T) { guestCappedPerClient(t, fx) })
	t.Run("ACaptchaIsCheckedWhenTheProjectAsksForOne", func(t *testing.T) { guestCaptcha(t, fx, turnstileDown) })
	t.Run("AGuestBecomesAFullAccountByProvingAnAddress", func(t *testing.T) { guestUpgradesByAddressChange(t, fx) })
	t.Run("AGuestBecomesAFullAccountByLinkingAProvider", func(t *testing.T) { guestUpgradesByProvider(t, fx) })
	t.Run("AGuestCannotTakeAProvenAddress", func(t *testing.T) { guestCannotTakeProvenAddress(t, fx) })
	t.Run("GuestAddressChangesAreCappedPerClient", func(t *testing.T) { guestChangesCappedPerClient(t, fx) })
	t.Run("AGuestCannotSetAPasswordBeforeItHasAnAddress", func(t *testing.T) { guestCannotSetPassword(t, fx) })
	t.Run("TheSubjectIsTheIDAndTheAddressItsOwnClaimOnlyWithTheFlag", func(t *testing.T) { tokenShapeFollowsTheFlag(t, fx) })
	t.Run("TheSweeperDeletesIdleGuestsOnlyWhileGuestsAreOn", func(t *testing.T) { guestSweeper(t, fx) })
}

func (fx *otpFixture) signInAsGuest(t *testing.T) map[string]any {
	t.Helper()
	resp, body := fx.call(http.MethodPost, guestPath, "", map[string]string{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("guest sign-in: %d %v", resp.StatusCode, body)
	}
	return body
}

// staleGuestToken is the guest's access token as it reads an hour after sign-in.
func (fx *otpFixture) staleGuestToken(t *testing.T, userID int64, role string) string {
	t.Helper()
	guest := true
	signed, err := fx.jwtSvc.Sign(auth.Claims{Sub: strconv.FormatInt(userID, 10), UserID: userID, ProjectID: "test-project",
		Role: role, AllowedRoles: []string{role}, Scope: "authenticated", IsGuest: &guest,
		AuthTime: time.Now().Add(-time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func guestSignsIn(t *testing.T, fx *otpFixture) {
	session := fx.signInAsGuest(t)
	user, _ := session["user"].(map[string]any)
	if user["isGuest"] != true || user["email"] != "" || userIDOf(session) <= 0 || refreshTokenOf(session) == "" {
		t.Fatalf("session = %v", session)
	}
	claims := jwtPayload(t, accessTokenOf(session))
	wantSub := strconv.FormatInt(int64(userIDOf(session)), 10)
	if claims["sub"] != wantSub || claims["role"] != "guest" || claims["is_guest"] != true ||
		claims["scope"] != "authenticated" || claims["email_verified"] != false {
		t.Fatalf("claims = %v", claims)
	}
	if _, ok := claims["email"]; ok {
		t.Fatalf("a guest token carries an address: %v", claims)
	}
	if roles, _ := claims["allowed_roles"].([]any); len(roles) != 1 || roles[0] != "guest" {
		t.Fatalf("allowed_roles = %v", claims["allowed_roles"])
	}
	if other := fx.signInAsGuest(t); userIDOf(other) == userIDOf(session) {
		t.Fatal("two guest sign-ins share an account")
	}
	if got := fx.getUser(t, accessTokenOf(session)); got["isGuest"] != true || got["email"] != "" {
		t.Fatalf("GET /user = %v", got)
	}
}

func guestRefreshes(t *testing.T, fx *otpFixture) {
	session := fx.signInAsGuest(t)
	fx.settings.set(func(s *signInSettings) { s.requireVerification = true })
	defer fx.settings.set(func(s *signInSettings) { s.requireVerification = false })
	resp, refreshed := fx.refreshWith(refreshTokenOf(session))
	if resp.StatusCode != http.StatusOK || userIDOf(refreshed) != userIDOf(session) {
		t.Fatalf("refresh: %d %v", resp.StatusCode, refreshed)
	}
	if claims := jwtPayload(t, accessTokenOf(refreshed)); claims["sub"] != jwtPayload(t, accessTokenOf(session))["sub"] || claims["is_guest"] != true {
		t.Fatalf("refreshed claims = %v", claims)
	}
}

func guestFailsClosed(t *testing.T, fx *otpFixture) {
	off := false
	defer fx.settings.set(func(s *signInSettings) {
		on := true
		s.guests, s.infoDown, s.allowNewUsers = &on, false, true
	})
	before := fx.count(t, "users")
	for _, c := range []struct {
		name   string
		change func(*signInSettings)
		status int
		code   string
	}{
		{"flag off", func(s *signInSettings) { s.guests = nil }, http.StatusNotFound, codeMethodOff},
		{"switch off", func(s *signInSettings) { s.guests = &off }, http.StatusNotFound, codeMethodOff},
		{"settings unreadable", func(s *signInSettings) { s.infoDown = true }, http.StatusServiceUnavailable, errSettingsUnreadable},
		{"sign-ups closed", func(s *signInSettings) {
			on := true
			s.guests, s.infoDown, s.allowNewUsers = &on, false, false
		}, http.StatusForbidden, codeSignupDisabled},
	} {
		fx.settings.set(c.change)
		if resp, body := fx.call(http.MethodPost, guestPath, "", nil); resp.StatusCode != c.status || body["error"] != c.code {
			t.Errorf("%s: %d %v", c.name, resp.StatusCode, body)
		}
	}
	// A body that would be refused still answers as a route that is off.
	fx.settings.set(func(s *signInSettings) { s.guests = nil })
	oversized := map[string]string{"captchaToken": strings.Repeat("a", maxCaptchaToken+1)}
	if resp, body := fx.call(http.MethodPost, guestPath, "", oversized); resp.StatusCode != http.StatusNotFound {
		t.Errorf("flag off with a bad body: %d %v", resp.StatusCode, body)
	}
	if fx.count(t, "users") != before {
		t.Fatal("a refused guest sign-in made an account")
	}
}

func guestRefreshAfterSwitchOff(t *testing.T, fx *otpFixture) {
	session := fx.signInAsGuest(t)
	off, on := false, true
	fx.settings.set(func(s *signInSettings) { s.guests = &off })
	resp, refreshed := fx.refreshWith(refreshTokenOf(session))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh with the project switch off: %d %v", resp.StatusCode, refreshed)
	}
	fx.settings.set(func(s *signInSettings) { s.guests = nil })
	resp, body := fx.refreshWith(refreshTokenOf(refreshed))
	fx.settings.set(func(s *signInSettings) { s.guests = &on })
	if resp.StatusCode != http.StatusForbidden || body["error"] != codeMethodOff {
		t.Fatalf("refresh with the flag off: %d %v", resp.StatusCode, body)
	}
	if resp, body := fx.refreshWith(refreshTokenOf(refreshed)); resp.StatusCode != http.StatusOK {
		t.Fatalf("the refused refresh spent the token: %d %v", resp.StatusCode, body)
	}
}

func guestCappedPerClient(t *testing.T, fx *otpFixture) {
	fx.handler.guestLimits = store.GuestLimits{PerClientHour: fx.count(t, "guest_sign_ups") + 1, PerProjectDay: 100000}
	defer func() { fx.handler.guestLimits = store.GuestLimits{PerClientHour: 1000, PerProjectDay: 100000} }()
	fx.signInAsGuest(t)
	resp, body := fx.call(http.MethodPost, guestPath, "", nil)
	if resp.StatusCode != http.StatusTooManyRequests || body["error"] != codeRateLimited || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("past the client's budget: %d %v", resp.StatusCode, body)
	}
}

func guestCaptcha(t *testing.T, fx *otpFixture, turnstileDown *bool) {
	fx.settings.set(func(s *signInSettings) { s.guestCaptcha = true })
	defer fx.settings.set(func(s *signInSettings) { s.guestCaptcha, s.captchaSecretMissing = false, false })
	before := fx.count(t, "users")
	for _, c := range []struct {
		name    string
		token   string
		prepare func()
		status  int
		code    string
	}{
		{"no token", "", func() {}, http.StatusBadRequest, codeCaptchaRequired},
		{"a wrong token", "turnstile-fail", func() {}, http.StatusBadRequest, codeCaptchaFailed},
		{"Turnstile down", turnstilePass, func() { *turnstileDown = true }, http.StatusServiceUnavailable, codeCaptchaUnavailable},
		{"no secret", turnstilePass, func() {
			*turnstileDown = false
			fx.settings.set(func(s *signInSettings) { s.captchaSecretMissing = true })
		}, http.StatusServiceUnavailable, codeCaptchaUnavailable},
	} {
		c.prepare()
		resp, body := fx.call(http.MethodPost, guestPath, "", map[string]string{"captchaToken": c.token})
		if resp.StatusCode != c.status || body["error"] != c.code {
			t.Errorf("%s: %d %v", c.name, resp.StatusCode, body)
		}
	}
	if fx.count(t, "users") != before {
		t.Fatal("a refused captcha made an account")
	}
	fx.settings.set(func(s *signInSettings) { s.captchaSecretMissing = false })
	if resp, body := fx.call(http.MethodPost, guestPath, "", map[string]string{"captchaToken": turnstilePass}); resp.StatusCode != http.StatusOK {
		t.Fatalf("a passing token: %d %v", resp.StatusCode, body)
	}
}

// assertFullAccount refreshes and checks the account kept its id and left the guest role.
func (fx *otpFixture) assertFullAccount(t *testing.T, refreshToken string, guestID float64, address string) {
	t.Helper()
	resp, refreshed := fx.refreshWith(refreshToken)
	if resp.StatusCode != http.StatusOK || userIDOf(refreshed) != guestID {
		t.Fatalf("refresh after the upgrade: %d %v", resp.StatusCode, refreshed)
	}
	claims := jwtPayload(t, accessTokenOf(refreshed))
	if claims["role"] != "user" || claims["is_guest"] != false || claims["email"] != address ||
		claims["sub"] != strconv.FormatInt(int64(guestID), 10) || claims["email_verified"] != true {
		t.Fatalf("claims after the upgrade = %v", claims)
	}
	if user, _ := refreshed["user"].(map[string]any); user["isGuest"] != nil || user["email"] != address {
		t.Fatalf("user after the upgrade = %v", user)
	}
}

func guestUpgradesByAddressChange(t *testing.T, fx *otpFixture) {
	session := fx.signInAsGuest(t)
	guestID := userIDOf(session)
	target := mailbox("guest-upgrade")
	fx.sender.reset()
	stale := fx.staleGuestToken(t, int64(guestID), "guest")
	resp, answer := fx.call(http.MethodPatch, userPath, stale, map[string]any{"email": target, "emailRedirectTo": appCallback})
	if resp.StatusCode != http.StatusOK || answer["emailChangeRequested"] != true {
		t.Fatalf("request: %d %v", resp.StatusCode, answer)
	}
	msg, tokenHash := fx.changeLink(t)
	if msg.To != target {
		t.Fatalf("confirmation mail = %+v", msg)
	}
	for _, sent := range fx.sender.all() {
		if sent.Template == email.TemplateEmailChangeNotice {
			t.Fatalf("a notice went out for a guest with no address: %+v", sent)
		}
	}
	if resp, body := fx.call(http.MethodPost, confirmEmailPath, stale, map[string]string{"token_hash": tokenHash}); resp.StatusCode != http.StatusOK {
		t.Fatalf("confirm: %d %v", resp.StatusCode, body)
	}
	fx.assertFullAccount(t, refreshTokenOf(session), guestID, target)
}

func guestUpgradesByProvider(t *testing.T, fx *otpFixture) {
	session := fx.signInAsGuest(t)
	guestID := userIDOf(session)
	github := person("guest-github")
	fx.sender.reset()
	resp, linked := fx.link(t, fx.staleGuestToken(t, int64(guestID), "guest"), "github", github)
	if resp.StatusCode != http.StatusOK || userIDOf(linked) != guestID {
		t.Fatalf("link: %d %v", resp.StatusCode, linked)
	}
	if notice := mailTo(fx.sender.all(), email.TemplateIdentityLinked, github.Email); notice != nil {
		t.Fatalf("the upgrade mailed a link notice: %+v", notice)
	}
	fx.assertFullAccount(t, refreshTokenOf(linked), guestID, github.Email)
	if again := fx.signIn(t, "github", github); userIDOf(again) != guestID {
		t.Fatalf("github signs in to %v, want the upgraded guest %v", userIDOf(again), guestID)
	}
}

func guestCannotTakeProvenAddress(t *testing.T, fx *otpFixture) {
	holder := person("guest-holder")
	fx.signIn(t, "google", holder)
	session := fx.signInAsGuest(t)
	resp, body := fx.link(t, fx.staleGuestToken(t, int64(userIDOf(session)), "guest"), "github", holder)
	if resp.StatusCode != http.StatusConflict || body["error"] != codeIdentityExists {
		t.Fatalf("linking a provider on a proven address: %d %v", resp.StatusCode, body)
	}
	if user := fx.getUser(t, accessTokenOf(session)); user["isGuest"] != true || user["email"] != "" {
		t.Fatalf("the refused guest changed: %v", user)
	}
}

func tokenShapeFollowsTheFlag(t *testing.T, fx *otpFixture) {
	defer fx.settings.set(func(s *signInSettings) {
		on := true
		s.guests, s.stableSubject = &on, true
	})
	fx.settings.set(func(s *signInSettings) { s.guests, s.stableSubject = nil, false })
	session, address := fx.passwordAccount(t, "token-shape")
	claims := jwtPayload(t, accessTokenOf(session))
	if claims["sub"] != address || claims["email"] != address {
		t.Fatalf("flag off: %v", claims)
	}
	if _, ok := claims["is_guest"]; ok {
		t.Fatalf("flag off carries is_guest: %v", claims)
	}
	on := true
	fx.settings.set(func(s *signInSettings) { s.guests, s.stableSubject = &on, true })
	// Tokens follow the flag once the cached settings are read again, as a
	// guest sign-in reads them.
	fx.signInAsGuest(t)
	resp, refreshed := fx.refreshWith(refreshTokenOf(session))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %d %v", resp.StatusCode, refreshed)
	}
	claims = jwtPayload(t, accessTokenOf(refreshed))
	if claims["sub"] != strconv.FormatInt(int64(userIDOf(session)), 10) || claims["email"] != address || claims["is_guest"] != false {
		t.Fatalf("flag on: %v", claims)
	}
	validated := postJSON(fx.srv, oauthProject+"/validate", map[string]string{"token": accessTokenOf(refreshed)})
	var body map[string]any
	decodeJSON(validated, &body)
	if body["email"] != address || body["sub"] != claims["sub"] {
		t.Fatalf("validate = %v", body)
	}
}

func guestSweeper(t *testing.T, fx *otpFixture) {
	idle := fx.signInAsGuest(t)
	fx.backdate(t, int64(userIDOf(idle)), 40*24*time.Hour)
	active := fx.signInAsGuest(t)
	fx.settings.set(func(s *signInSettings) { s.guests = nil })
	fx.handler.SweepGuests(context.Background())
	if resp, _ := fx.call(http.MethodGet, userPath, accessTokenOf(idle), nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("the sweeper ran with the flag off: %d", resp.StatusCode)
	}
	on := true
	fx.settings.set(func(s *signInSettings) { s.guests = &on })
	fx.handler.SweepGuests(context.Background())
	if resp, _ := fx.call(http.MethodGet, userPath, accessTokenOf(idle), nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("the idle guest survived: %d", resp.StatusCode)
	}
	if resp, _ := fx.call(http.MethodGet, userPath, accessTokenOf(active), nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("the active guest was deleted: %d", resp.StatusCode)
	}
}

func TestIntegration_ADisabledAccountCannotRefresh(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx := newPostgresOTPFixture(t)
	session, address := fx.passwordAccount(t, "disabled-refresh")
	fx.disable(t, address)
	if resp, body := fx.refreshWith(refreshTokenOf(session)); resp.StatusCode != http.StatusForbidden || body["error"] != errAccountDisabled.Error() {
		t.Fatalf("refresh of a disabled account: %d %v", resp.StatusCode, body)
	}
}

func guestChangesCappedPerClient(t *testing.T, fx *otpFixture) {
	saved := fx.handler.emailChangeLimits
	defer func() { fx.handler.emailChangeLimits = saved }()
	fx.handler.emailChangeLimits.PerGuestClientDay = fx.count(t, "email_change_tokens") + 1
	request := func() (*http.Response, map[string]any) {
		guest := userIDOf(fx.signInAsGuest(t))
		token := fx.staleGuestToken(t, int64(guest), "guest")
		return fx.call(http.MethodPatch, userPath, token, map[string]any{"email": mailbox("guest-capped"), "emailRedirectTo": appCallback})
	}
	if resp, body := request(); resp.StatusCode != http.StatusOK {
		t.Fatalf("first change from the client: %d %v", resp.StatusCode, body)
	}
	if resp, body := request(); resp.StatusCode != http.StatusTooManyRequests || body["error"] != codeRateLimited {
		t.Fatalf("past the client's guest budget: %d %v", resp.StatusCode, body)
	}
}

func guestCannotSetPassword(t *testing.T, fx *otpFixture) {
	guest := userIDOf(fx.signInAsGuest(t))
	token := fx.staleGuestToken(t, int64(guest), "guest")
	resp, body := fx.call(http.MethodPatch, userPath, token, map[string]any{"password": "a-long-enough-password"})
	if resp.StatusCode != http.StatusBadRequest || body["error"] != codeAddressRequired {
		t.Fatalf("a guest set a password: %d %v", resp.StatusCode, body)
	}
}
