package handler

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/email"
	"github.com/excalibase/auth/internal/store"
)

func TestIntegration_AccountSelfServiceOnPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	runAccountFlows(t, newPostgresOTPFixture(t))
}

func TestIntegration_AccountSelfServiceOnMySQL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	runAccountFlows(t, newMySQLOTPFixture(t))
}

func runAccountFlows(t *testing.T, fx *otpFixture) {
	t.Run("TheUserReadsTheAccountAndItsMetadata", func(t *testing.T) { userReadsAccount(t, fx) })
	t.Run("UserMetadataMergesAndAppMetadataIsNotTheUsers", func(t *testing.T) { userMetadataMerges(t, fx) })
	t.Run("MetadataNeverReachesTheToken", func(t *testing.T) { metadataStaysOutOfTheToken(t, fx) })
	t.Run("APasswordChangeNeedsTheCurrentPasswordOrARecentSignIn", func(t *testing.T) { passwordChange(t, fx) })
	t.Run("AnAddressChangeIsProvenByTheNewInboxAndNoticedByTheOld", func(t *testing.T) { emailChange(t, fx) })
	t.Run("AnAddressChangeSaysTheSameWhetherOrNotTheAddressIsTaken", func(t *testing.T) { emailChangeTakenSilently(t, fx) })
	t.Run("AnAddressChangeNeedsARecentSignInAndAProvenAccount", func(t *testing.T) { emailChangeRefusals(t, fx) })
	t.Run("SignOutEndsThisTheOthersOrEverySession", func(t *testing.T) { signOutScopes(t, fx) })
	t.Run("TheProjectReadsWritesAndDeletesAccounts", func(t *testing.T) { adminAccounts(t, fx) })
	t.Run("OffOrUnreadableSettingsRefuseEveryNewRoute", func(t *testing.T) { accountFailsClosed(t, fx) })
}

const (
	userPath         = oauthProject + "/user"
	confirmEmailPath = oauthProject + "/user/email/confirm"
)

// passwordAccount registers an account with a password and returns its session.
func (fx *otpFixture) passwordAccount(t *testing.T, name string) (map[string]any, string) {
	t.Helper()
	address := mailbox(name)
	session := tokenResponse(t, postJSON(fx.srv, oauthProject+"/register", map[string]string{
		"email": address, "password": oauthPassword, "fullName": "Name " + name}), "register")
	return session, address
}

func (fx *otpFixture) getUser(t *testing.T, bearer string) map[string]any {
	t.Helper()
	resp, body := fx.call(http.MethodGet, userPath, bearer, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /user: %d %v", resp.StatusCode, body)
	}
	return body
}

func (fx *otpFixture) refreshWith(refreshToken string) (*http.Response, map[string]any) {
	return fx.call(http.MethodPost, oauthProject+"/token", "", map[string]string{
		"grant_type": "refresh_token", "refresh_token": refreshToken})
}

func refreshTokenOf(body map[string]any) string {
	token, _ := body["refreshToken"].(string)
	return token
}

func userReadsAccount(t *testing.T, fx *otpFixture) {
	google := person("user-read")
	session := fx.signIn(t, "google", google)
	user := fx.getUser(t, accessTokenOf(session))
	if user["email"] != google.Email || user["emailVerified"] != true || user["hasPassword"] != false || user["id"] != userIDOf(session) {
		t.Fatalf("user = %v", user)
	}
	if meta, ok := user["userMetadata"].(map[string]any); !ok || len(meta) != 0 {
		t.Fatalf("userMetadata = %v", user["userMetadata"])
	}
	if meta, ok := user["appMetadata"].(map[string]any); !ok || len(meta) != 0 {
		t.Fatalf("appMetadata = %v", user["appMetadata"])
	}
	if resp, body := fx.call(http.MethodGet, userPath, "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: %d %v", resp.StatusCode, body)
	}
}

func userMetadataMerges(t *testing.T, fx *otpFixture) {
	session, _ := fx.passwordAccount(t, "user-meta")
	bearer := accessTokenOf(session)
	resp, body := fx.call(http.MethodPatch, userPath, bearer, map[string]any{
		"fullName": "Renamed", "data": map[string]any{"theme": "dark", "prefs": map[string]any{"lang": "vi"}}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch: %d %v", resp.StatusCode, body)
	}
	resp, body = fx.call(http.MethodPatch, userPath, bearer, map[string]any{"data": map[string]any{"theme": nil}})
	user, _ := body["user"].(map[string]any)
	meta, _ := user["userMetadata"].(map[string]any)
	if resp.StatusCode != http.StatusOK || user["fullName"] != "Renamed" || len(meta) != 1 || meta["prefs"] == nil {
		t.Fatalf("after removing a key: %d %v", resp.StatusCode, body)
	}
	if resp, body := fx.call(http.MethodPatch, userPath, bearer, map[string]any{"appMetadata": map[string]any{"plan": "pro"}}); resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Fatalf("a user writing app metadata: %d %v", resp.StatusCode, body)
	}
	if app, _ := fx.getUser(t, bearer)["appMetadata"].(map[string]any); len(app) != 0 {
		t.Fatalf("app metadata changed: %v", app)
	}
	for _, refused := range []struct {
		body map[string]any
		code string
	}{
		{map[string]any{"data": []int{1}}, "invalid_metadata"},
		{map[string]any{"data": "text"}, "invalid_metadata"},
		{map[string]any{"data": map[string]any{"blob": strings.Repeat("x", store.MaxMetadataBytes)}}, "metadata_too_large"},
		{map[string]any{"fullName": "  "}, "invalid_full_name"},
		{map[string]any{"password": "short"}, ""},
		{map[string]any{"password": "brand-new-password", "email": mailbox("both")}, codeOneSensitiveChange},
		{map[string]any{"data": map[string]any{"nul": "a\u0000b"}}, "invalid_metadata"},
	} {
		resp, body := fx.call(http.MethodPatch, userPath, bearer, refused.body)
		if resp.StatusCode != http.StatusBadRequest || (refused.code != "" && body["error"] != refused.code) {
			t.Errorf("%v: %d %v", refused.body, resp.StatusCode, body)
		}
	}
}

func metadataStaysOutOfTheToken(t *testing.T, fx *otpFixture) {
	session, _ := fx.passwordAccount(t, "user-token")
	if resp, body := fx.call(http.MethodPatch, userPath, accessTokenOf(session), map[string]any{
		"data": map[string]any{"role": "service", "nested": map[string]any{"a": 1}}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("patch: %d %v", resp.StatusCode, body)
	}
	resp, refreshed := fx.refreshWith(refreshTokenOf(session))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %d %v", resp.StatusCode, refreshed)
	}
	claims := jwtPayload(t, accessTokenOf(refreshed))
	if claims["role"] != "user" || claims["nested"] != nil || claims["user_metadata"] != nil || claims["userMetadata"] != nil {
		t.Fatalf("metadata reached the token: %v", claims)
	}
}

func passwordChange(t *testing.T, fx *otpFixture) {
	session, address := fx.passwordAccount(t, "user-password")
	stale := fx.staleToken(t, session, time.Now().Add(-10*time.Minute))
	for _, body := range []map[string]any{
		{"password": "brand-new-password"},
		{"password": "brand-new-password", "currentPassword": "not-the-password"},
	} {
		if resp, answer := fx.call(http.MethodPatch, userPath, stale, body); resp.StatusCode != http.StatusForbidden || answer["error"] != codeReauthRequired {
			t.Fatalf("%v with an old sign-in: %d %v", body, resp.StatusCode, answer)
		}
	}
	other, _ := fx.passwordAccount(t, "user-password-other")
	resp, answer := fx.call(http.MethodPatch, userPath, stale, map[string]any{"password": "brand-new-password", "currentPassword": oauthPassword})
	fresh, _ := answer["session"].(map[string]any)
	if resp.StatusCode != http.StatusOK || accessTokenOf(fresh) == "" {
		t.Fatalf("change with the current password: %d %v", resp.StatusCode, answer)
	}
	if resp, _ := fx.refreshWith(refreshTokenOf(session)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the old session survived the change: %d", resp.StatusCode)
	}
	if resp, _ := fx.refreshWith(refreshTokenOf(other)); resp.StatusCode != http.StatusOK {
		t.Fatalf("another account's session ended: %d", resp.StatusCode)
	}
	if claims := jwtPayload(t, accessTokenOf(fresh)); claims["auth_time"] != jwtPayload(t, stale)["auth_time"] {
		t.Fatalf("a password change moved the sign-in time: %v", claims["auth_time"])
	}
	login := postJSON(fx.srv, oauthProject+"/login", map[string]string{"email": address, "password": "brand-new-password"})
	tokenResponse(t, login, "login with the new password")
	recent, _ := fx.passwordAccount(t, "user-password-recent")
	if resp, answer := fx.call(http.MethodPatch, userPath, accessTokenOf(recent), map[string]any{"password": "another-new-password"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("change after a recent sign-in: %d %v", resp.StatusCode, answer)
	}
	provider := fx.signIn(t, "github", person("user-password-set"))
	if resp, answer := fx.call(http.MethodPatch, userPath, accessTokenOf(provider), map[string]any{"password": "a-first-password"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("a provider account setting its first password: %d %v", resp.StatusCode, answer)
	}
}

// changeLink is the token_hash of the last address-change mail.
func (fx *otpFixture) changeLink(t *testing.T) (email.Message, string) {
	t.Helper()
	for _, msg := range fx.sender.all() {
		if msg.Template != email.TemplateEmailChange {
			continue
		}
		link, err := url.Parse(msg.Data["linkUrl"])
		if err != nil || link.Query().Get("type") != "email_change" {
			t.Fatalf("link = %q", msg.Data["linkUrl"])
		}
		return msg, link.Query().Get("token_hash")
	}
	t.Fatalf("no address-change mail in %v", fx.sender.all())
	return email.Message{}, ""
}

func mailTo(messages []email.Message, template, to string) *email.Message {
	for i := range messages {
		if messages[i].Template == template && messages[i].To == to {
			return &messages[i]
		}
	}
	return nil
}

func emailChange(t *testing.T, fx *otpFixture) {
	google := person("user-change")
	session := fx.signIn(t, "google", google)
	target := mailbox("user-change-target")
	fx.sender.reset()
	resp, answer := fx.call(http.MethodPatch, userPath, accessTokenOf(session), map[string]any{"email": target, "emailRedirectTo": appCallback})
	if resp.StatusCode != http.StatusOK || answer["emailChangeRequested"] != true {
		t.Fatalf("request: %d %v", resp.StatusCode, answer)
	}
	if user, _ := answer["user"].(map[string]any); user["email"] != google.Email {
		t.Fatalf("the address changed before it was proven: %v", user)
	}
	msg, tokenHash := fx.changeLink(t)
	if msg.To != target || !strings.HasPrefix(msg.Data["linkUrl"], appCallback+"?") || msg.ProjectID != "test-project" {
		t.Fatalf("confirmation mail = %+v", msg)
	}
	notice := mailTo(fx.sender.all(), email.TemplateEmailChangeNotice, google.Email)
	if notice == nil || notice.Data["newEmail"] != target {
		t.Fatalf("no notice to the old address in %v", fx.sender.all())
	}
	bearer := accessTokenOf(session)
	if resp, body := fx.call(http.MethodPost, confirmEmailPath, bearer, map[string]string{"token_hash": tokenHash + "x"}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a wrong link: %d %v", resp.StatusCode, body)
	}
	if resp, body := fx.call(http.MethodPost, confirmEmailPath, "", map[string]string{"token_hash": tokenHash}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a link spent with no session: %d %v", resp.StatusCode, body)
	}
	victim := fx.signIn(t, "github", person("user-change-clicker"))
	if resp, body := fx.call(http.MethodPost, confirmEmailPath, accessTokenOf(victim), map[string]string{"token_hash": tokenHash}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a link spent by another account's session: %d %v", resp.StatusCode, body)
	}
	if resp, body := fx.call(http.MethodPost, confirmEmailPath, bearer, map[string]string{"token_hash": tokenHash}); resp.StatusCode != http.StatusOK {
		t.Fatalf("confirm: %d %v", resp.StatusCode, body)
	}
	if resp, body := fx.call(http.MethodPost, confirmEmailPath, bearer, map[string]string{"token_hash": tokenHash}); resp.StatusCode != http.StatusBadRequest || body["error"] != errTokenNotRedeemable.Error() {
		t.Fatalf("a link spent twice: %d %v", resp.StatusCode, body)
	}
	resp, refreshed := fx.refreshWith(refreshTokenOf(session))
	if resp.StatusCode != http.StatusOK || jwtPayload(t, accessTokenOf(refreshed))["sub"] != target {
		t.Fatalf("refresh after the change: %d %v", resp.StatusCode, refreshed)
	}
	if again := fx.signIn(t, "google", google); userIDOf(again) != userIDOf(session) {
		t.Fatal("the provider no longer reaches the moved account")
	}
}

func emailChangeTakenSilently(t *testing.T, fx *otpFixture) {
	holder := person("user-change-holder")
	fx.signIn(t, "github", holder)
	session := fx.signIn(t, "google", person("user-change-prober"))
	fx.sender.reset()
	taken, takenBody := fx.call(http.MethodPatch, userPath, accessTokenOf(session), map[string]any{"email": holder.Email})
	takenMail := fx.sender.all()
	if len(takenMail) != 1 || takenMail[0].Template != email.TemplateEmailChangeNotice {
		t.Fatalf("a taken address: want only the notice to the own address, got %v", takenMail)
	}
	time.Sleep(testChangeInterval)
	fx.sender.reset()
	free, freeBody := fx.call(http.MethodPatch, userPath, accessTokenOf(session), map[string]any{"email": mailbox("user-change-free")})
	if len(fx.sender.all()) != 2 {
		t.Fatalf("a free address: want the link and the notice, got %v", fx.sender.all())
	}
	if taken.StatusCode != free.StatusCode || takenBody["emailChangeRequested"] != freeBody["emailChangeRequested"] {
		t.Fatalf("taken %d %v, free %d %v", taken.StatusCode, takenBody, free.StatusCode, freeBody)
	}
}

func emailChangeRefusals(t *testing.T, fx *otpFixture) {
	session := fx.signIn(t, "google", person("user-change-stale"))
	stale := fx.staleToken(t, session, time.Now().Add(-10*time.Minute))
	if resp, body := fx.call(http.MethodPatch, userPath, stale, map[string]any{"email": mailbox("x")}); resp.StatusCode != http.StatusForbidden || body["error"] != codeReauthRequired {
		t.Fatalf("old sign-in: %d %v", resp.StatusCode, body)
	}
	unproven, _ := fx.passwordAccount(t, "user-change-unproven")
	if resp, body := fx.call(http.MethodPatch, userPath, accessTokenOf(unproven), map[string]any{"email": mailbox("y")}); resp.StatusCode != http.StatusForbidden || body["error"] != codeEmailUnverified {
		t.Fatalf("unproven account: %d %v", resp.StatusCode, body)
	}
	for _, body := range []map[string]any{
		{"email": "not an address"},
		{"email": "ünïcode@example.test"},
		{"email": mailbox("z"), "emailRedirectTo": "https://evil.test/"},
	} {
		if resp, answer := fx.call(http.MethodPatch, userPath, accessTokenOf(session), body); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%v: %d %v", body, resp.StatusCode, answer)
		}
	}
}

func (fx *otpFixture) logout(scope, bearer, refreshToken string) (*http.Response, map[string]any) {
	path := oauthProject + "/logout"
	if scope != "" {
		path += "?scope=" + scope
	}
	return fx.call(http.MethodPost, path, bearer, map[string]string{"refreshToken": refreshToken})
}

func signOutScopes(t *testing.T, fx *otpFixture) {
	first, address := fx.passwordAccount(t, "user-signout")
	login := func() map[string]any {
		return tokenResponse(t, postJSON(fx.srv, oauthProject+"/login", map[string]string{"email": address, "password": oauthPassword}), "login")
	}
	second, third := login(), login()
	if resp, body := fx.logout("others", "", refreshTokenOf(first)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("others without a token: %d %v", resp.StatusCode, body)
	}
	if resp, body := fx.logout("everything", accessTokenOf(first), refreshTokenOf(first)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown scope: %d %v", resp.StatusCode, body)
	}
	stranger, _ := fx.passwordAccount(t, "user-signout-stranger")
	if resp, body := fx.logout("others", accessTokenOf(first), refreshTokenOf(stranger)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("others keeping another account's session: %d %v", resp.StatusCode, body)
	}
	if resp, body := fx.logout("others", accessTokenOf(first), refreshTokenOf(first)); resp.StatusCode != http.StatusOK {
		t.Fatalf("others: %d %v", resp.StatusCode, body)
	}
	if resp, _ := fx.refreshWith(refreshTokenOf(second)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("another session survived scope=others: %d", resp.StatusCode)
	}
	if resp, _ := fx.refreshWith(refreshTokenOf(stranger)); resp.StatusCode != http.StatusOK {
		t.Fatalf("another account was signed out: %d", resp.StatusCode)
	}
	resp, kept := fx.refreshWith(refreshTokenOf(first))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scope=others ended this session: %d", resp.StatusCode)
	}
	if resp, body := fx.logout("global", accessTokenOf(kept), ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("global: %d %v", resp.StatusCode, body)
	}
	for _, refresh := range []string{refreshTokenOf(kept), refreshTokenOf(third)} {
		if resp, _ := fx.refreshWith(refresh); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("a session survived scope=global: %d", resp.StatusCode)
		}
	}
	local := login()
	if resp, body := fx.logout("", "", refreshTokenOf(local)); resp.StatusCode != http.StatusOK {
		t.Fatalf("local sign-out: %d %v", resp.StatusCode, body)
	}
}

func adminPath(id float64) string {
	return oauthProject + "/users/" + strconv.FormatInt(int64(id), 10)
}

func adminAccounts(t *testing.T, fx *otpFixture) {
	session, address := fx.passwordAccount(t, "user-admin")
	service := mintServiceToken(t, fx.jwtSvc, "test-project", 9)
	path := adminPath(userIDOf(session))
	if resp, body := fx.call(http.MethodPatch, path, service, map[string]any{"appMetadata": map[string]any{"plan": "pro", "tier": 2}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("set app metadata: %d %v", resp.StatusCode, body)
	}
	resp, detail := fx.call(http.MethodPatch, path, service, map[string]any{"appMetadata": map[string]any{"tier": nil}, "userMetadata": map[string]any{"note": "x"}})
	app, _ := detail["appMetadata"].(map[string]any)
	if resp.StatusCode != http.StatusOK || detail["email"] != address || len(app) != 1 || app["plan"] != "pro" || detail["role"] != "user" {
		t.Fatalf("merge app metadata: %d %v", resp.StatusCode, detail)
	}
	if user := fx.getUser(t, accessTokenOf(session)); user["appMetadata"].(map[string]any)["plan"] != "pro" {
		t.Fatalf("the user does not read the app metadata: %v", user)
	}
	if resp, body := fx.call(http.MethodGet, path, accessTokenOf(session), nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("an end user reading the admin route: %d %v", resp.StatusCode, body)
	}
	if resp, body := fx.call(http.MethodPatch, path, service, map[string]any{"role": "admin"}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("an unknown field: %d %v", resp.StatusCode, body)
	}
	if resp, body := fx.call(http.MethodDelete, path, service, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: %d %v", resp.StatusCode, body)
	}
	if resp, _ := fx.call(http.MethodGet, path, service, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a deleted account still reads: %d", resp.StatusCode)
	}
	if resp, _ := fx.refreshWith(refreshTokenOf(session)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a deleted account's session survived: %d", resp.StatusCode)
	}
}

func accountFailsClosed(t *testing.T, fx *otpFixture) {
	session, _ := fx.passwordAccount(t, "user-off")
	service := mintServiceToken(t, fx.jwtSvc, "test-project", 9)
	routes := []struct {
		method, path, bearer string
		body                 any
	}{
		{http.MethodGet, userPath, accessTokenOf(session), nil},
		{http.MethodPatch, userPath, accessTokenOf(session), map[string]any{"fullName": "Off"}},
		{http.MethodPost, confirmEmailPath, "", map[string]string{"token_hash": "x"}},
		{http.MethodPost, oauthProject + "/logout?scope=global", accessTokenOf(session), map[string]string{}},
		{http.MethodGet, adminPath(userIDOf(session)), service, nil},
		{http.MethodPatch, adminPath(userIDOf(session)), service, map[string]any{"appMetadata": map[string]any{}}},
		{http.MethodDelete, adminPath(userIDOf(session)), service, nil},
	}
	for _, state := range []struct {
		change func(*signInSettings)
		want   int
	}{
		{func(s *signInSettings) { s.userAPI = false }, http.StatusNotFound},
		{func(s *signInSettings) { s.userAPI, s.infoDown = true, true }, http.StatusServiceUnavailable},
	} {
		fx.settings.set(state.change)
		for _, route := range routes {
			if resp, body := fx.call(route.method, route.path, route.bearer, route.body); resp.StatusCode != state.want {
				t.Errorf("%s %s: %d %v, want %d", route.method, route.path, resp.StatusCode, body, state.want)
			}
		}
	}
	fx.settings.set(func(s *signInSettings) { s.userAPI, s.infoDown = false, false })
	if resp, body := fx.logout("", "", refreshTokenOf(session)); resp.StatusCode != http.StatusOK {
		t.Errorf("local sign-out with the flag off: %d %v", resp.StatusCode, body)
	}
	fx.settings.set(func(s *signInSettings) { s.userAPI = true })
}
