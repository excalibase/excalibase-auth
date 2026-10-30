package handler

import (
	"encoding/base32"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/mfa"
)

const factorsPath = oauthProject + "/factors"

func mfaFixture(t *testing.T, mysql bool) *otpFixture {
	var fx *otpFixture
	if mysql {
		fx = newMySQLOTPFixture(t)
	} else {
		fx = newPostgresOTPFixture(t)
	}
	fx.settings.set(func(s *signInSettings) { s.mfa = true })
	return fx
}

func TestIntegration_MultiFactorOnPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	runMFAFlows(t, mfaFixture(t, false))
}

func TestIntegration_MultiFactorOnMySQL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	runMFAFlows(t, mfaFixture(t, true))
}

func runMFAFlows(t *testing.T, fx *otpFixture) {
	t.Run("OffOrUnreadableSettingsRefuseEveryRouteAndTokensCarryNoLevel", func(t *testing.T) { mfaFailsClosed(t, fx) })
	t.Run("ATOTPFactorTakesASessionFromAal1ToAal2AndRefreshKeepsIt", func(t *testing.T) { mfaStepUp(t, fx) })
	t.Run("ACodeIsNeverAcceptedTwice", func(t *testing.T) { mfaNoReplay(t, fx) })
	t.Run("AnAal1SessionCannotChangeHowAnEnrolledAccountSignsIn", func(t *testing.T) { mfaNeedsAal2(t, fx) })
	t.Run("ARecoveryCodeGivesAal2Once", func(t *testing.T) { mfaRecovery(t, fx) })
	t.Run("WrongCodesLockAFactorEvenForTheRightCode", func(t *testing.T) { mfaBruteForce(t, fx) })
	t.Run("ARefreshTokenOfAnotherAccountIsRefused", func(t *testing.T) { mfaOtherSession(t, fx) })
	t.Run("UnenrollingAtAal2RemovesTheFactorAndItsCodes", func(t *testing.T) { mfaUnenroll(t, fx) })
	t.Run("AMissingProjectKeyFailsClosed", func(t *testing.T) { mfaKeyMissing(t, fx) })
	t.Run("AnAdminResetRemovesFactorsAndEndsSessions", func(t *testing.T) { mfaAdminReset(t, fx) })
	t.Run("GuestsHaveNoSecondFactor", func(t *testing.T) { mfaGuestRefused(t, fx) })
	t.Run("AFactorPlantedWithAStolenPasswordNeverLiftsAal1", func(t *testing.T) { mfaPlantedFactor(t, fx) })
}

func mfaPlantedFactor(t *testing.T, fx *otpFixture) {
	steadyStep(t)
	owner, address := fx.passwordAccount(t, "mfa-planted")
	attacker := fx.passwordLogin(t, address)
	planted := fx.enroll(t, accessTokenOf(attacker), "Attacker")
	mine := fx.enroll(t, accessTokenOf(owner), "Phone")
	resp, elevated := fx.verifyAt(t, owner, mine, -1)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner verify: %d %v", resp.StatusCode, elevated)
	}
	if resp, _ := fx.call(http.MethodPost, factorsPath+"/"+planted.id+"/challenge", accessTokenOf(attacker), nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("the planted factor survived the owner's first factor: %d", resp.StatusCode)
	}
	second := fx.enroll(t, accessTokenOf(elevated), "Tablet")
	weak := fx.passwordLogin(t, address)
	if resp, body := fx.verifyAt(t, weak, second, 0); resp.StatusCode != http.StatusForbidden || errorOf(body) != codeInsufficientAAL {
		t.Fatalf("aal1 verified an unverified second factor: %d %v", resp.StatusCode, body)
	}
}

// enrolment is a factor as POST /factors answers it, with its decoded secret.
type enrolment struct {
	id     string
	secret []byte
}

func (fx *otpFixture) enroll(t *testing.T, bearer, name string) enrolment {
	t.Helper()
	resp, body := fx.call(http.MethodPost, factorsPath, bearer, map[string]string{"factorType": "totp", "friendlyName": name, "issuer": "Acme"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("enroll: %d %v", resp.StatusCode, body)
	}
	totp, _ := body["totp"].(map[string]any)
	encoded, _ := totp["secret"].(string)
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil || len(secret) != mfa.SecretBytes || body["status"] != "unverified" || body["factorType"] != "totp" {
		t.Fatalf("enrolment = %v (%v)", body, err)
	}
	if uri, _ := totp["uri"].(string); !strings.HasPrefix(uri, "otpauth://totp/Acme:") || !strings.Contains(uri, "secret="+encoded) {
		t.Fatalf("uri = %q", uri)
	}
	id, _ := body["id"].(string)
	return enrolment{id: id, secret: secret}
}

func (fx *otpFixture) challenge(t *testing.T, bearer, factorID string) string {
	t.Helper()
	resp, body := fx.call(http.MethodPost, factorsPath+"/"+factorID+"/challenge", bearer, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("challenge: %d %v", resp.StatusCode, body)
	}
	id, _ := body["id"].(string)
	return id
}

// verifyAt answers a fresh challenge with the code of now plus offset steps.
func (fx *otpFixture) verifyAt(t *testing.T, session map[string]any, factor enrolment, offset int64) (*http.Response, map[string]any) {
	t.Helper()
	bearer := accessTokenOf(session)
	code := mfa.Code(factor.secret, mfa.StepAt(time.Now())+offset)
	return fx.call(http.MethodPost, factorsPath+"/"+factor.id+"/verify", bearer, map[string]string{
		"challengeId": fx.challenge(t, bearer, factor.id), "code": code, "refreshToken": refreshTokenOf(session)})
}

func (fx *otpFixture) passwordLogin(t *testing.T, address string) map[string]any {
	t.Helper()
	return tokenResponse(t, postJSON(fx.srv, oauthProject+"/login", map[string]string{"email": address, "password": oauthPassword}), "login")
}

func assertLevel(t *testing.T, session map[string]any, aal string, amr ...string) {
	t.Helper()
	claims := jwtPayload(t, accessTokenOf(session))
	var methods []string
	for _, method := range asSlice(claims["amr"]) {
		text, _ := method.(string)
		methods = append(methods, text)
	}
	if claims["aal"] != aal || !slices.Equal(methods, amr) {
		t.Fatalf("aal=%v amr=%v, want %s %v", claims["aal"], claims["amr"], aal, amr)
	}
}

func asSlice(value any) []any {
	items, _ := value.([]any)
	return items
}

func errorOf(body map[string]any) string {
	message, _ := body["error"].(string)
	return message
}

func mfaFailsClosed(t *testing.T, fx *otpFixture) {
	session, _ := fx.passwordAccount(t, "mfa-off")
	defer fx.settings.set(func(s *signInSettings) { s.mfa, s.infoDown = true, false })
	fx.settings.set(func(s *signInSettings) { s.mfa = false })
	if resp, body := fx.call(http.MethodGet, factorsPath, accessTokenOf(session), nil); resp.StatusCode != http.StatusNotFound || errorOf(body) != codeMethodOff {
		t.Fatalf("flag off: %d %v", resp.StatusCode, body)
	}
	refreshed := tokenResponse(t, postJSON(fx.srv, oauthProject+"/refresh", map[string]string{"refreshToken": refreshTokenOf(session)}), "refresh")
	if claims := jwtPayload(t, accessTokenOf(refreshed)); claims["aal"] != nil || claims["amr"] != nil {
		t.Fatalf("a token carries a level while MFA is off: %v", claims)
	}
	fx.settings.set(func(s *signInSettings) { s.mfa, s.infoDown = true, true })
	if resp, _ := fx.call(http.MethodPost, factorsPath, accessTokenOf(refreshed), map[string]string{"factorType": "totp"}); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("settings unreadable: %d", resp.StatusCode)
	}
	fx.settings.set(func(s *signInSettings) { s.infoDown = false })
	if resp, _ := fx.call(http.MethodGet, factorsPath, "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: %d", resp.StatusCode)
	}
}

// steadyStep waits until the current time step has a few seconds left, so a
// test that reasons about steps does not cross into the next one midway.
func steadyStep(t *testing.T) {
	t.Helper()
	period := int64(mfa.Period / time.Second)
	if left := period - time.Now().Unix()%period; left < 8 {
		time.Sleep(time.Duration(left+1) * time.Second)
	}
}

func mfaStepUp(t *testing.T, fx *otpFixture) {
	steadyStep(t)
	_, address := fx.passwordAccount(t, "mfa-step-up")
	session := fx.passwordLogin(t, address)
	assertLevel(t, session, "aal1", "password")
	factor := fx.enroll(t, accessTokenOf(session), "Phone")
	resp, body := fx.call(http.MethodGet, factorsPath, accessTokenOf(session), nil)
	factors := asSlice(body["factors"])
	if resp.StatusCode != http.StatusOK || len(factors) != 1 || body["recoveryCodesRemaining"] != float64(0) {
		t.Fatalf("list: %d %v", resp.StatusCode, body)
	}
	if wrong, wrongBody := fx.call(http.MethodPost, factorsPath+"/"+factor.id+"/verify", accessTokenOf(session), map[string]string{
		"challengeId": fx.challenge(t, accessTokenOf(session), factor.id), "code": "000000", "refreshToken": refreshTokenOf(session),
	}); wrong.StatusCode != http.StatusBadRequest || errorOf(wrongBody) != codeInvalidCode {
		t.Fatalf("wrong code: %d %v", wrong.StatusCode, wrongBody)
	}
	resp, elevated := fx.verifyAt(t, session, factor, -1)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify: %d %v", resp.StatusCode, elevated)
	}
	assertLevel(t, elevated, "aal2", "password", "totp")
	if codes := asSlice(elevated["recoveryCodes"]); len(codes) != mfa.RecoveryCodeCount {
		t.Fatalf("recovery codes = %v", elevated["recoveryCodes"])
	}
	refreshed := tokenResponse(t, postJSON(fx.srv, oauthProject+"/refresh", map[string]string{"refreshToken": refreshTokenOf(elevated)}), "refresh")
	assertLevel(t, refreshed, "aal2", "password", "totp")
	if claims := jwtPayload(t, accessTokenOf(refreshed)); claims["auth_time"] == nil {
		t.Fatalf("refresh lost auth_time: %v", claims)
	}
	_, body = fx.call(http.MethodGet, factorsPath, accessTokenOf(refreshed), nil)
	listed, _ := asSlice(body["factors"])[0].(map[string]any)
	if listed["status"] != "verified" || body["recoveryCodesRemaining"] != float64(mfa.RecoveryCodeCount) {
		t.Fatalf("after verify: %v", body)
	}
	if second := fx.loginAndVerifyFails(t, address, factor, -1); second != codeInvalidCode {
		t.Fatalf("the spent step: %s", second)
	}
	again := fx.passwordLogin(t, address)
	assertLevel(t, again, "aal1", "password")
	if resp, body := fx.verifyAt(t, again, factor, 0); resp.StatusCode != http.StatusOK || body["recoveryCodes"] != nil {
		t.Fatalf("a later verify: %d %v", resp.StatusCode, body)
	}
	// The aal1 token the step-up spent is a replay now: the whole session ends.
	if old, _ := fx.refreshWith(refreshTokenOf(session)); old.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the aal1 refresh token outlived the step-up: %d", old.StatusCode)
	}
	if resp, _ := fx.refreshWith(refreshTokenOf(refreshed)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replaying the spent aal1 token left its session live: %d", resp.StatusCode)
	}
}

// loginAndVerifyFails signs in again and answers a fresh challenge with the
// given step, returning the refusal code.
func (fx *otpFixture) loginAndVerifyFails(t *testing.T, address string, factor enrolment, offset int64) string {
	t.Helper()
	session := fx.passwordLogin(t, address)
	resp, body := fx.verifyAt(t, session, factor, offset)
	if resp.StatusCode == http.StatusOK {
		t.Fatal("verify succeeded")
	}
	return errorOf(body)
}

// enrolled is an account at aal2 with one verified factor and its recovery codes.
func (fx *otpFixture) enrolled(t *testing.T, name string) (map[string]any, string, enrolment) {
	t.Helper()
	session, address := fx.passwordAccount(t, name)
	factor := fx.enroll(t, accessTokenOf(session), "Phone")
	resp, elevated := fx.verifyAt(t, session, factor, -1)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify: %d %v", resp.StatusCode, elevated)
	}
	return elevated, address, factor
}

func mfaNoReplay(t *testing.T, fx *otpFixture) {
	steadyStep(t)
	_, address, factor := fx.enrolled(t, "mfa-replay")
	for _, offset := range []int64{-1, -2} {
		if got := fx.loginAndVerifyFails(t, address, factor, offset); got != codeInvalidCode {
			t.Fatalf("offset %d: %s", offset, got)
		}
	}
	if got := fx.loginAndVerifyFails(t, address, factor, 2); got != codeInvalidCode {
		t.Fatalf("two steps ahead: %s", got)
	}
}

func mfaNeedsAal2(t *testing.T, fx *otpFixture) {
	elevated, address, factor := fx.enrolled(t, "mfa-aal2")
	weak := accessTokenOf(fx.passwordLogin(t, address))
	refusals := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, factorsPath, map[string]string{"factorType": "totp", "friendlyName": "Attacker"}},
		{http.MethodDelete, factorsPath + "/" + factor.id, nil},
		{http.MethodPost, factorsPath + "/recovery-codes", nil},
		{http.MethodPatch, userPath, map[string]string{"password": "another-password-1", "currentPassword": oauthPassword}},
		{http.MethodDelete, identitiesPath + "/999999", nil},
	}
	for _, refusal := range refusals {
		resp, body := fx.call(refusal.method, refusal.path, weak, refusal.body)
		if resp.StatusCode != http.StatusForbidden || errorOf(body) != codeInsufficientAAL {
			t.Errorf("%s %s at aal1: %d %v", refusal.method, refusal.path, resp.StatusCode, body)
		}
	}
	resp, body := fx.call(http.MethodPost, factorsPath, accessTokenOf(elevated), map[string]string{"factorType": "totp", "friendlyName": "Tablet"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("enroll at aal2: %d %v", resp.StatusCode, body)
	}
	resp, body = fx.call(http.MethodPost, factorsPath+"/recovery-codes", accessTokenOf(elevated), nil)
	if resp.StatusCode != http.StatusOK || len(asSlice(body["recoveryCodes"])) != mfa.RecoveryCodeCount {
		t.Fatalf("regenerate at aal2: %d %v", resp.StatusCode, body)
	}
	resp, body = fx.call(http.MethodPatch, userPath, accessTokenOf(elevated), map[string]string{"password": "another-password-1", "currentPassword": oauthPassword})
	changed, _ := body["session"].(map[string]any)
	if resp.StatusCode != http.StatusOK || changed == nil {
		t.Fatalf("password change at aal2: %d %v", resp.StatusCode, body)
	}
	assertLevel(t, changed, "aal2", "password", "totp")
}

func mfaRecovery(t *testing.T, fx *otpFixture) {
	elevated, address, _ := fx.enrolled(t, "mfa-recovery")
	code, _ := asSlice(elevated["recoveryCodes"])[3].(string)
	weak := fx.passwordLogin(t, address)
	resp, recovered := fx.call(http.MethodPost, factorsPath+"/recovery", accessTokenOf(weak),
		map[string]string{"code": code, "refreshToken": refreshTokenOf(weak)})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("recovery: %d %v", resp.StatusCode, recovered)
	}
	assertLevel(t, recovered, "aal2", "password", "recovery")
	again := fx.passwordLogin(t, address)
	resp, body := fx.call(http.MethodPost, factorsPath+"/recovery", accessTokenOf(again),
		map[string]string{"code": code, "refreshToken": refreshTokenOf(again)})
	if resp.StatusCode != http.StatusBadRequest || errorOf(body) != codeInvalidCode {
		t.Fatalf("spent code again: %d %v", resp.StatusCode, body)
	}
	if resp, _ := fx.refreshWith(refreshTokenOf(again)); resp.StatusCode != http.StatusOK {
		t.Fatalf("a refused recovery spent the session: %d", resp.StatusCode)
	}
	_, listing := fx.call(http.MethodGet, factorsPath, accessTokenOf(recovered), nil)
	if listing["recoveryCodesRemaining"] != float64(mfa.RecoveryCodeCount-1) {
		t.Fatalf("remaining = %v", listing["recoveryCodesRemaining"])
	}
}

func mfaBruteForce(t *testing.T, fx *otpFixture) {
	_, address, factor := fx.enrolled(t, "mfa-brute")
	session := fx.passwordLogin(t, address)
	bearer := accessTokenOf(session)
	for attempt := range 5 {
		resp, body := fx.call(http.MethodPost, factorsPath+"/"+factor.id+"/verify", bearer, map[string]string{
			"challengeId": fx.challenge(t, bearer, factor.id), "code": "000000", "refreshToken": refreshTokenOf(session)})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("wrong code %d: %d %v", attempt, resp.StatusCode, body)
		}
	}
	resp, body := fx.verifyAt(t, session, factor, 0)
	if resp.StatusCode != http.StatusTooManyRequests || errorOf(body) != codeTooManyAttempts {
		t.Fatalf("right code past the budget: %d %v", resp.StatusCode, body)
	}
}

func mfaOtherSession(t *testing.T, fx *otpFixture) {
	_, address, factor := fx.enrolled(t, "mfa-mine")
	stranger, _ := fx.passwordAccount(t, "mfa-stranger")
	mine := fx.passwordLogin(t, address)
	bearer := accessTokenOf(mine)
	resp, body := fx.call(http.MethodPost, factorsPath+"/"+factor.id+"/verify", bearer, map[string]string{
		"challengeId": fx.challenge(t, bearer, factor.id), "code": mfa.Code(factor.secret, mfa.StepAt(time.Now())),
		"refreshToken": refreshTokenOf(stranger)})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("another account's refresh token: %d %v", resp.StatusCode, body)
	}
	if resp, _ := fx.refreshWith(refreshTokenOf(stranger)); resp.StatusCode != http.StatusOK {
		t.Fatalf("the stranger's session was spent: %d", resp.StatusCode)
	}
	if resp, _ := fx.call(http.MethodPost, factorsPath+"/"+factor.id+"/challenge", accessTokenOf(stranger), nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a challenge for another account's factor: %d", resp.StatusCode)
	}
}

func mfaUnenroll(t *testing.T, fx *otpFixture) {
	elevated, address, factor := fx.enrolled(t, "mfa-unenroll")
	if resp, body := fx.call(http.MethodDelete, factorsPath+"/"+factor.id, accessTokenOf(elevated), nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unenroll: %d %v", resp.StatusCode, body)
	}
	_, listing := fx.call(http.MethodGet, factorsPath, accessTokenOf(elevated), nil)
	if len(asSlice(listing["factors"])) != 0 || listing["recoveryCodesRemaining"] != float64(0) {
		t.Fatalf("after unenroll: %v", listing)
	}
	weak := fx.passwordLogin(t, address)
	if resp, body := fx.call(http.MethodPost, factorsPath, accessTokenOf(weak), map[string]string{"factorType": "totp"}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("with no verified factor aal1 enrols: %d %v", resp.StatusCode, body)
	}
}

func mfaKeyMissing(t *testing.T, fx *otpFixture) {
	session, _ := fx.passwordAccount(t, "mfa-no-key")
	defer fx.settings.set(func(s *signInSettings) { s.mfaKeyMissing = false })
	fx.settings.set(func(s *signInSettings) { s.mfaKeyMissing = true })
	if resp, body := fx.call(http.MethodPost, factorsPath, accessTokenOf(session), map[string]string{"factorType": "totp"}); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("enroll with no key: %d %v", resp.StatusCode, body)
	}
}

func mfaAdminReset(t *testing.T, fx *otpFixture) {
	elevated, _, _ := fx.enrolled(t, "mfa-reset")
	service, err := fx.jwtSvc.Sign(auth.Claims{Sub: "apikey:1", ProjectID: "test-project", Role: auth.RoleService,
		AllowedRoles: []string{auth.RoleService}, Scope: "service", KeyID: 1})
	if err != nil {
		t.Fatal(err)
	}
	userID := int64(userIDOf(elevated))
	path := oauthProject + "/users/" + strconv.FormatInt(userID, 10) + "/factors"
	if resp, _ := fx.call(http.MethodDelete, path, accessTokenOf(elevated), nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("an end user reset through the admin route: %d", resp.StatusCode)
	}
	if resp, body := fx.call(http.MethodDelete, path, service, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("reset: %d %v", resp.StatusCode, body)
	}
	if resp, _ := fx.refreshWith(refreshTokenOf(elevated)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a session survived the reset: %d", resp.StatusCode)
	}
	if resp, _ := fx.call(http.MethodDelete, oauthProject+"/users/999999999/factors", service, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown user: %d", resp.StatusCode)
	}
}

func mfaGuestRefused(t *testing.T, fx *otpFixture) {
	on := true
	defer fx.settings.set(func(s *signInSettings) { s.guests = nil })
	fx.settings.set(func(s *signInSettings) { s.guests = &on })
	guest := fx.signInAsGuest(t)
	if resp, body := fx.call(http.MethodPost, factorsPath, accessTokenOf(guest), map[string]string{"factorType": "totp"}); resp.StatusCode != http.StatusForbidden || errorOf(body) != codeAddressRequired {
		t.Fatalf("a guest enrolled: %d %v", resp.StatusCode, body)
	}
}
