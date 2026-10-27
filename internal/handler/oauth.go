package handler

import (
	"context"
	"crypto/subtle"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/oauth"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/store"
	"github.com/excalibase/auth/internal/token"
	"github.com/go-chi/chi/v5"
)

const (
	// flowTTL bounds how long a sign-in may sit at the provider.
	flowTTL = 10 * time.Minute
	// authCodeTTL bounds how long the app has to redeem its code.
	authCodeTTL = 5 * time.Minute
	// defaultSignInMaxAge is how stale the sign-in settings may be.
	defaultSignInMaxAge = 30 * time.Second
	providerTimeout     = 10 * time.Second
	maxFullName         = 100
	maxRedirectLength   = 2048
	// maxEmailLength is users.email's width.
	maxEmailLength = 100
)

// Codes the app sees on its redirect URL; never the provider's own text.
const (
	codeAccessDenied      = "access_denied"
	codeServerError       = "server_error"
	codeUnavailable       = "temporarily_unavailable"
	codeMethodOff         = "method_not_enabled"
	codeEmailUnverified   = "email_not_verified"
	codeSignupDisabled    = "signup_disabled"
	codeAccountDisabled   = "account_disabled"
	codeInvalidEmail      = "invalid_email"
	codeRateLimited       = "rate_limited"
	errSettingsUnreadable = "sign-in settings are unavailable, retry shortly"
)

var (
	errRedirectNotAllowed = errors.New("redirect_to is not an allowed redirect URL")
	errChallengeRequired  = errors.New("code_challenge with code_challenge_method=S256 is required")
	errFlowInvalid        = errors.New("sign-in state is invalid or has expired")
	errInvalidGrant       = errors.New("invalid or expired code")
	errSignupDisabled     = errors.New(codeSignupDisabled)
)

// WithOAuthProviders replaces the sign-in providers and the HTTP client that
// reaches them; tests point both at a fake.
func (h *AuthHandler) WithOAuthProviders(providers map[string]oauth.Provider, client *http.Client) *AuthHandler {
	h.oauthProviders = providers
	h.oauthHTTP = client
	return h
}

func defaultOAuthProviders() map[string]oauth.Provider {
	return map[string]oauth.Provider{
		"google": oauth.Google(oauth.GoogleEndpoints),
		"github": oauth.GitHub(oauth.GitHubEndpoints),
	}
}

// signInSettings reads the project's settings no older than signInMaxAge;
// an unreadable control plane is an error, never a default.
func (h *AuthHandler) signInSettings(ctx context.Context, projectID string) (pool.ProjectInfo, error) {
	return h.poolMgr.GetProjectInfoWithin(ctx, projectID, h.signInMaxAge)
}

// signupsOpen reads the sign-up switch no older than signInMaxAge. A project
// whose control plane never sent the switch (the flag off) keeps today's
// behaviour when it cannot be read; one that did fails closed.
func (h *AuthHandler) signupsOpen(ctx context.Context, projectID string) (bool, error) {
	info, err := h.signInSettings(ctx, projectID)
	if err == nil {
		return info.NewUsersAllowed(), nil
	}
	if cached, ok := h.poolMgr.CachedProjectInfo(projectID); ok && cached.AllowNewUsers != nil {
		return false, err
	}
	return true, nil
}

// enabledProvider is a provider this service knows and the project switched on.
func (h *AuthHandler) enabledProvider(info pool.ProjectInfo, name string) (oauth.Provider, pool.OAuthProvider, bool) {
	provider, known := h.oauthProviders[name]
	settings, enabled := info.OAuthProvider(name)
	return provider, settings, known && enabled
}

func allowedRedirects(info pool.ProjectInfo) []string {
	return append([]string{info.SiteURL}, info.RedirectURLs...)
}

// Authorize starts a provider sign-in. Everything is checked before the
// browser leaves: the provider, the redirect URL and the app's PKCE challenge.
func (h *AuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	projectID := projectKey(r)
	query := r.URL.Query()
	if ticket := query.Get("link_ticket"); ticket != "" {
		h.authorizeLink(w, r, ticket)
		return
	}
	info, err := h.signInSettings(r.Context(), projectID)
	if err != nil {
		httpError(w, errSettingsUnreadable, http.StatusServiceUnavailable)
		return
	}
	provider, settings, ok := h.enabledProvider(info, query.Get("provider"))
	if !ok {
		httpError(w, codeMethodOff, http.StatusNotFound)
		return
	}
	redirectTo, ok := oauth.AllowedRedirect(query.Get("redirect_to"), allowedRedirects(info))
	if !ok || len(redirectTo) > maxRedirectLength {
		httpError(w, errRedirectNotAllowed.Error(), http.StatusBadRequest)
		return
	}
	challenge := query.Get("code_challenge")
	if query.Get("code_challenge_method") != "S256" || !oauth.ValidChallenge(challenge) {
		httpError(w, errChallengeRequired.Error(), http.StatusBadRequest)
		return
	}
	db, ok := h.storeFor(w, r)
	if !ok {
		return
	}
	h.startAtProvider(w, r, db, provider, settings, store.FlowState{ClientCodeChallenge: challenge, RedirectTo: redirectTo})
}

// startAtProvider saves the flow under a new state, binds it to this browser
// and sends the browser to the provider.
func (h *AuthHandler) startAtProvider(w http.ResponseWriter, r *http.Request, db store.Store, provider oauth.Provider, settings pool.OAuthProvider, app store.FlowState) {
	flow, err := oauth.NewFlow()
	if err != nil {
		httpError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := db.SaveFlowState(r.Context(), store.FlowState{
		StateHash: token.Hash(flow.State), Provider: provider.Name, IDPCodeVerifier: flow.Verifier, Nonce: flow.Nonce,
		ClientCodeChallenge: app.ClientCodeChallenge, RedirectTo: app.RedirectTo, LinkUserID: app.LinkUserID,
		ExpiresAt: time.Now().Add(flowTTL),
	}); err != nil {
		httpError(w, "failed to start sign-in", http.StatusInternalServerError)
		return
	}
	bindToBrowser(w, settings.CallbackURL, flow.State)
	client := oauth.Client{ID: settings.ClientID, RedirectURL: settings.CallbackURL}
	redirect(w, r, provider.AuthCodeURL(client, flow))
}

// Callback finishes a provider sign-in and hands the app a single-use code.
// Without a live state there is no trusted place to send the browser, so that
// answer is plain JSON; every later failure goes back to the app as a code.
func (h *AuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	projectID := projectKey(r)
	query := r.URL.Query()
	if !boundToBrowser(r, query.Get("state")) {
		httpError(w, errFlowInvalid.Error(), http.StatusBadRequest)
		return
	}
	clearBrowserBinding(w, r, query.Get("state"))
	db, err := h.poolMgr.GetStore(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		writePoolFailure(w, err)
		return
	}
	flow, err := db.ConsumeFlowState(r.Context(), token.Hash(query.Get("state")))
	// A link ticket's row has no provider verifier; it is never a state.
	if err != nil || flow.Provider != chi.URLParam(r, "provider") || flow.IDPCodeVerifier == "" {
		httpError(w, errFlowInvalid.Error(), http.StatusBadRequest)
		return
	}
	if providerError := query.Get("error"); providerError != "" {
		code := codeServerError
		if providerError == codeAccessDenied {
			code = codeAccessDenied
		}
		redirect(w, r, oauth.WithError(flow.RedirectTo, code))
		return
	}
	code, failure := h.finishSignIn(r.Context(), db, projectID, flow, query.Get("code"), h.clientIP(r))
	if failure != "" {
		redirect(w, r, oauth.WithError(flow.RedirectTo, failure))
		return
	}
	redirect(w, r, oauth.WithParam(flow.RedirectTo, "code", code))
}

// finishSignIn returns the app's code, or the error code to send it instead.
func (h *AuthHandler) finishSignIn(ctx context.Context, db store.Store, projectID string, flow store.FlowState, providerCode, clientIP string) (string, string) {
	info, err := h.signInSettings(ctx, projectID)
	if err != nil {
		return "", codeUnavailable
	}
	provider, settings, ok := h.enabledProvider(info, flow.Provider)
	if !ok {
		return "", codeMethodOff
	}
	secret, err := h.poolMgr.ProviderSecret(ctx, projectID, flow.Provider)
	if err != nil {
		log.Printf("auth.oauth.secret_unavailable project=%s provider=%s", safeLog(projectID), flow.Provider)
		return "", codeUnavailable
	}
	callCtx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()
	client := oauth.Client{ID: settings.ClientID, Secret: secret, RedirectURL: settings.CallbackURL}
	identity, err := provider.Identify(callCtx, h.oauthHTTP, client, providerCode, flow.IDPCodeVerifier, flow.Nonce)
	if err != nil {
		log.Printf("auth.oauth.identify_failed project=%s provider=%s err=%v", safeLog(projectID), flow.Provider, err)
		if errors.Is(err, oauth.ErrEmailNotVerified) {
			return "", codeEmailUnverified
		}
		return "", codeServerError
	}
	if len(identity.Email) > maxEmailLength {
		return "", codeInvalidEmail
	}
	if flow.LinkUserID != 0 {
		// Written only when the app redeems the code with its verifier.
		link := store.IdentityClaim{Provider: flow.Provider, Subject: identity.Subject, Email: identity.Email}
		return h.issueAuthCode(ctx, db, store.AuthCode{UserID: flow.LinkUserID, CodeChallenge: flow.ClientCodeChallenge, Link: link})
	}
	account, outcome, failure := h.signInIdentity(ctx, db, projectID, flow.Provider, identity, info.NewUsersAllowed())
	if failure != "" {
		return "", failure
	}
	h.audit(ctx, db, projectID, store.AuditEvent{UserID: account.ID, Method: flow.Provider, IP: clientIP}, outcome)
	if outcome == store.IdentityLinked {
		h.noticeLinked(ctx, db, projectID, account.ID, flow.Provider, identity.Email)
	}
	return h.issueAuthCode(ctx, db, store.AuthCode{UserID: account.ID, CodeChallenge: flow.ClientCodeChallenge})
}

func (h *AuthHandler) signInIdentity(ctx context.Context, db store.Store, projectID, provider string, identity oauth.Identity, allowCreate bool) (store.Account, store.IdentityOutcome, string) {
	claim := store.IdentityClaim{Provider: provider, Subject: identity.Subject, Email: identity.Email, FullName: displayName(identity)}
	// Only a new account spends the sign-up budget /register draws on.
	account, outcome, err := db.SignInWithIdentity(ctx, claim, false)
	if errors.Is(err, store.ErrSignupsDisabled) && allowCreate {
		if h.limits != nil && !h.limits.AllowSignup(projectID) {
			return store.Account{}, 0, codeRateLimited
		}
		account, outcome, err = db.SignInWithIdentity(ctx, claim, true)
	}
	switch {
	case errors.Is(err, store.ErrSignupsDisabled):
		return store.Account{}, 0, codeSignupDisabled
	case errors.Is(err, store.ErrAccountDisabled):
		return store.Account{}, 0, codeAccountDisabled
	case err != nil:
		log.Printf("auth.oauth.account_failed project=%s provider=%s", safeLog(projectID), provider)
		return store.Account{}, 0, codeServerError
	case !account.Enabled:
		return store.Account{}, 0, codeAccountDisabled
	}
	if err := (accountRoles{role: account.Role, allowed: account.AllowedRoles}).validate(); err != nil {
		return store.Account{}, 0, codeAccessDenied
	}
	log.Printf("auth.oauth.signed_in project=%s provider=%s userId=%d outcome=%d", safeLog(projectID), provider, account.ID, outcome)
	return account, outcome, ""
}

func (h *AuthHandler) issueAuthCode(ctx context.Context, db store.Store, code store.AuthCode) (string, string) {
	plaintext, hash, err := token.New()
	if err != nil {
		return "", codeServerError
	}
	code.CodeHash, code.ExpiresAt = hash, time.Now().Add(authCodeTTL)
	if err := db.SaveAuthCode(ctx, code); err != nil {
		return "", codeServerError
	}
	return plaintext, ""
}

// displayName fills the required full name from the provider, else the address.
func displayName(identity oauth.Identity) string {
	name := strings.TrimSpace(identity.Name)
	if name == "" {
		name, _, _ = strings.Cut(identity.Email, "@")
	}
	if utf8.RuneCountInString(name) > maxFullName {
		name = string([]rune(name)[:maxFullName])
	}
	return name
}

// exchangePKCE redeems the code a provider sign-in handed the app. A wrong
// verifier spends the code too, so it cannot be guessed at.
func (h *AuthHandler) exchangePKCE(r *http.Request, projectID, code, verifier string) (*domain.AuthResponse, int, error) {
	info, err := h.signInSettings(r.Context(), projectID)
	if err != nil {
		return nil, http.StatusServiceUnavailable, errors.New(errSettingsUnreadable)
	}
	if !info.OAuthEnabled() {
		return nil, http.StatusBadRequest, errUnsupportedGrant
	}
	db, err := h.poolMgr.GetStore(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		status, perr := poolFailure(err)
		return nil, status, perr
	}
	redeemed, err := db.RedeemAuthCode(r.Context(), token.Hash(code))
	if err != nil || code == "" || !oauth.VerifierMatches(verifier, redeemed.CodeChallenge) {
		return nil, http.StatusBadRequest, errInvalidGrant
	}
	linking := redeemed.Link.Provider != ""
	if linking {
		if status, err := h.commitLink(r.Context(), db, projectID, redeemed.UserID, redeemed.Link, h.clientIP(r)); err != nil {
			return nil, status, err
		}
	}
	return h.accountSession(r, db, projectID, redeemed.UserID, !linking)
}

// redirect sends the browser on without leaking the URL onwards or caching it.
func redirect(w http.ResponseWriter, r *http.Request, target string) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusFound)
}

// noPasswordHash is a well-formed hash no password matches (its key is all
// zero bytes), checked for an account that has no password so that answer
// takes as long as a wrong password does.
const noPasswordHash = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func (h *AuthHandler) checkPassword(ctx context.Context, password, encoded string) (bool, error) {
	if encoded == "" {
		_, err := h.hasher.Check(ctx, password, noPasswordHash)
		return false, err
	}
	return h.hasher.Check(ctx, password, encoded)
}

// The state is also set as a cookie on the browser that started the sign-in,
// so a sign-in started by someone else cannot finish in the victim's browser.
// One cookie per state keeps sign-ins in two tabs apart.
const stateCookiePrefix = "excb_oauth_"

func stateCookieName(state string) string {
	return stateCookiePrefix + token.Hash(state)[:16]
}

func stateCookie(path, state string, secure bool, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: stateCookieName(state), Value: state, Path: path, MaxAge: maxAge, HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteLaxMode,
	}
}

// bindToBrowser scopes the cookie to the registered callback, whose org
// segment may differ from the one the app called /authorize with.
func bindToBrowser(w http.ResponseWriter, callbackURL, state string) {
	path, secure := "/", true
	if parsed, err := url.Parse(callbackURL); err == nil && parsed.Path != "" {
		path, secure = parsed.Path, parsed.Scheme == "https"
	}
	http.SetCookie(w, stateCookie(path, state, secure, int(flowTTL.Seconds())))
}

// clearBrowserBinding runs on the callback, whose path is the one the cookie was set for.
func clearBrowserBinding(w http.ResponseWriter, r *http.Request, state string) {
	http.SetCookie(w, stateCookie(r.URL.Path, state, r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https", -1))
}

func boundToBrowser(r *http.Request, state string) bool {
	if state == "" {
		return false
	}
	cookie, err := r.Cookie(stateCookieName(state))
	return err == nil && subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) == 1
}
