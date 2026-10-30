package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/email"
	"github.com/excalibase/auth/internal/middleware"
	"github.com/excalibase/auth/internal/oauth"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/store"
	"github.com/excalibase/auth/internal/token"
	"github.com/go-chi/chi/v5"
)

const (
	// reauthWindow is how recent a sign-in must be to change how the account signs in.
	reauthWindow = 5 * time.Minute
	// linkTicketTTL bounds the hop from the app's request to the browser reaching /authorize.
	linkTicketTTL = 2 * time.Minute
	maxLinkBody   = 4 << 10

	codeReauthRequired   = "reauthentication_required"
	codeIdentityExists   = "identity_already_exists"
	codeLastSignInMethod = "last_sign_in_method"
	codeIdentityNotFound = "identity_not_found"
)

type linkRequest struct {
	Provider            string `json:"provider"`
	RedirectTo          string `json:"redirect_to"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// IdentityRoutes lets a signed-in end user list, link and unlink the ways
// the account signs in. Routes mounts them behind RequireJWT.
func (h *AuthHandler) IdentityRoutes(r chi.Router) {
	r.Use(requireEndUser)
	r.Get("/", h.ListIdentities)
	r.With(h.limit(rateLimitToken)).Post("/authorize", h.StartProviderLink)
	r.With(h.limit(rateLimitOTP)).Post("/email", h.StartAddressLink)
	r.With(h.limit(rateLimitToken)).Delete("/{identityId}", h.UnlinkIdentity)
}

// requireEndUser admits only an access token of a signed-in end user of the
// project in the URL; api-key, admin and other projects' tokens are refused.
func requireEndUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFromContext(r.Context())
		switch {
		case claims == nil:
			httpError(w, "missing_token", http.StatusUnauthorized)
		case claims.ProjectID != projectKey(r):
			httpError(w, "token_project_mismatch", http.StatusForbidden)
		case !claims.IsAccess() || claims.UserID == 0 || claims.Scope != "authenticated":
			httpError(w, "insufficient_scope", http.StatusForbidden)
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// recentlySignedIn is whether the token's sign-in, which a refresh keeps, is
// within the window; a token that does not say when is never recent.
func recentlySignedIn(claims *auth.Claims, now time.Time) bool {
	if claims == nil || claims.AuthTime == 0 {
		return false
	}
	age := now.Sub(time.Unix(claims.AuthTime, 0))
	return age > -time.Minute && age <= reauthWindow
}

// freshEnough is a recent sign-in or, for a guest, which has nothing to sign
// in again with, a token issued within the window: refreshing proves the
// session's own long-lived credential.
func freshEnough(claims *auth.Claims, guest bool, now time.Time) bool {
	if recentlySignedIn(claims, now) {
		return true
	}
	if !guest || claims == nil || claims.IssuedAt == 0 {
		return false
	}
	age := now.Sub(time.Unix(claims.IssuedAt, 0))
	return age > -time.Minute && age <= reauthWindow
}

func freshEndUser(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	claims := middleware.ClaimsFromContext(r.Context())
	if !recentlySignedIn(claims, time.Now()) {
		httpError(w, codeReauthRequired, http.StatusForbidden)
		return nil, false
	}
	return claims, true
}

// freshLinker is freshEndUser that defers a guest's token to linkableFresh,
// which reads the account.
func freshLinker(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims != nil && claims.IsGuest != nil && *claims.IsGuest {
		return claims, true
	}
	return freshEndUser(w, r)
}

// linkableFresh is linkable for an account that signed in recently, or is a
// guest whose token is fresh.
func linkableFresh(w http.ResponseWriter, r *http.Request, db store.Store, claims *auth.Claims) bool {
	if !recentlySignedIn(claims, time.Now()) {
		account, err := db.AccountByID(r.Context(), claims.UserID)
		if err != nil {
			writeStoreFailure(w, err, errUserNotFound.Error())
			return false
		}
		if !freshEnough(claims, account.IsGuest, time.Now()) {
			httpError(w, codeReauthRequired, http.StatusForbidden)
			return false
		}
	}
	return linkable(w, r, db, claims.UserID)
}

// linkingSettings reads the settings fresh: 503 when unreadable, 404 when the
// project has no sign-in method an identity could be linked for.
func (h *AuthHandler) linkingSettings(w http.ResponseWriter, r *http.Request) (pool.ProjectInfo, bool) {
	info, err := h.signInSettings(r.Context(), projectKey(r))
	if err != nil {
		httpError(w, errSettingsUnreadable, http.StatusServiceUnavailable)
		return info, false
	}
	if !info.OAuthEnabled() && !info.EmailOTPEnabled {
		httpError(w, codeMethodOff, http.StatusNotFound)
		return info, false
	}
	return info, true
}

func (h *AuthHandler) storeFor(w http.ResponseWriter, r *http.Request) (store.Store, bool) {
	db, err := h.poolMgr.GetStore(r.Context(), chi.URLParam(r, "orgSlug"), projectKey(r))
	if err != nil {
		writePoolFailure(w, err)
		return nil, false
	}
	return db, true
}

// ListIdentities lists the caller's identities and whether the account has a password.
func (h *AuthHandler) ListIdentities(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.linkingSettings(w, r); !ok {
		return
	}
	db, ok := h.storeFor(w, r)
	if !ok {
		return
	}
	userID := middleware.ClaimsFromContext(r.Context()).UserID
	account, err := db.AccountByID(r.Context(), userID)
	if err != nil {
		writeStoreFailure(w, err, errUserNotFound.Error())
		return
	}
	identities, err := db.ListIdentities(r.Context(), userID)
	if err != nil {
		writeStoreFailure(w, err, errUserNotFound.Error())
		return
	}
	listed := make([]domain.Identity, 0, len(identities))
	for _, identity := range identities {
		listed = append(listed, domain.Identity{ID: identity.ID, Provider: identity.Provider, Email: identity.Email,
			CreatedAt: identity.CreatedAt, LastSignInAt: identity.LastSignInAt})
	}
	writeJSON(w, domain.IdentitiesResponse{Identities: listed, HasPassword: store.HasUsablePassword(account.PasswordHash)})
}

// StartProviderLink hands the app a short-lived ticket for /authorize, where
// the browser starts the provider sign-in that proves the new identity.
func (h *AuthHandler) StartProviderLink(w http.ResponseWriter, r *http.Request) {
	var req linkRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLinkBody)).Decode(&req); err != nil {
		httpError(w, "invalid request", http.StatusBadRequest)
		return
	}
	info, ok := h.linkingSettings(w, r)
	if !ok {
		return
	}
	claims, ok := freshLinker(w, r)
	if !ok {
		return
	}
	provider, _, ok := h.enabledProvider(info, req.Provider)
	if !ok {
		httpError(w, codeMethodOff, http.StatusNotFound)
		return
	}
	redirectTo, ok := oauth.AllowedRedirect(req.RedirectTo, allowedRedirects(info))
	if !ok || len(redirectTo) > maxRedirectLength {
		httpError(w, errRedirectNotAllowed.Error(), http.StatusBadRequest)
		return
	}
	if req.CodeChallengeMethod != "S256" || !oauth.ValidChallenge(req.CodeChallenge) {
		httpError(w, errChallengeRequired.Error(), http.StatusBadRequest)
		return
	}
	db, ok := h.storeFor(w, r)
	if !ok || !linkableFresh(w, r, db, claims) || !h.enrolledNeedsAAL2(w, r, info, db, claims) {
		return
	}
	ticket, _, err := token.New()
	if err != nil {
		httpError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := db.SaveFlowState(r.Context(), store.FlowState{
		StateHash: linkTicketHash(ticket), Provider: provider.Name, ClientCodeChallenge: req.CodeChallenge,
		RedirectTo: redirectTo, LinkUserID: claims.UserID, ExpiresAt: time.Now().Add(linkTicketTTL),
	}); err != nil {
		httpError(w, "failed to start linking", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"linkTicket": ticket, "expiresIn": int(linkTicketTTL.Seconds())})
}

// linkTicketHash is where a ticket is kept in flow_states. A state is
// attacker input, so a ticket row is told apart by its empty provider verifier.
func linkTicketHash(ticket string) string {
	return token.Hash("link|" + ticket)
}

// authorizeLink spends a ticket and sends the browser to the provider with a
// flow bound to the account the ticket was made for.
func (h *AuthHandler) authorizeLink(w http.ResponseWriter, r *http.Request, ticket string) {
	info, err := h.signInSettings(r.Context(), projectKey(r))
	if err != nil {
		httpError(w, errSettingsUnreadable, http.StatusServiceUnavailable)
		return
	}
	db, ok := h.storeFor(w, r)
	if !ok {
		return
	}
	pending, err := db.ConsumeFlowState(r.Context(), linkTicketHash(ticket))
	if err != nil || pending.LinkUserID == 0 || pending.IDPCodeVerifier != "" {
		httpError(w, errFlowInvalid.Error(), http.StatusBadRequest)
		return
	}
	provider, settings, ok := h.enabledProvider(info, pending.Provider)
	if !ok {
		httpError(w, codeMethodOff, http.StatusNotFound)
		return
	}
	if _, ok := oauth.AllowedRedirect(pending.RedirectTo, allowedRedirects(info)); !ok {
		httpError(w, errRedirectNotAllowed.Error(), http.StatusBadRequest)
		return
	}
	h.startAtProvider(w, r, db, provider, settings, pending)
}

// StartAddressLink emails a code or link to the address being linked. The
// answer is the one /otp gives; the link is written when /verify spends it.
func (h *AuthHandler) StartAddressLink(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeOTPRequest(w, r)
	if !ok {
		return
	}
	info, ok := h.emailSignInSettings(w, r)
	if !ok {
		return
	}
	claims, ok := freshLinker(w, r)
	if !ok {
		return
	}
	if !asciiOnly(req.Email) {
		httpError(w, errInvalidEmail.Error(), http.StatusBadRequest)
		return
	}
	redirectTo := ""
	if req.Type == store.OTPMagicLink {
		if redirectTo, ok = magicLinkTarget(w, req, info); !ok {
			return
		}
	}
	db, ok := h.storeFor(w, r)
	if !ok || !linkableFresh(w, r, db, claims) || !h.enrolledNeedsAAL2(w, r, info, db, claims) {
		return
	}
	projectID := projectKey(r)
	otp, msg, err := h.newEmailOTP(projectID, req, redirectTo, false)
	if err != nil {
		httpError(w, "internal error", http.StatusInternalServerError)
		return
	}
	msg.Template = linkTemplates[msg.Template]
	otp.LinkUserID, otp.Mailed, otp.IP = claims.UserID, true, otpSenderKey(h.clientIP(r))
	h.saveAndMail(w, r, db, projectID, otp, msg)
}

var linkTemplates = map[string]string{
	email.TemplateMagicLink: email.TemplateLinkMagicLink,
	email.TemplateEmailOTP:  email.TemplateLinkEmailOTP,
}

// asciiOnly keeps linked addresses to ones every engine and Go lower alike.
func asciiOnly(address string) bool {
	for i := 0; i < len(address); i++ {
		if address[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// linkable answers for an account that may not take a link before anything is
// saved or mailed for it.
func linkable(w http.ResponseWriter, r *http.Request, db store.Store, userID int64) bool {
	if status, err := linkFailure(db.LinkableAccount(r.Context(), userID)); err != nil {
		httpError(w, err.Error(), status)
		return false
	}
	return true
}

func linkFailure(err error) (int, error) {
	switch {
	case err == nil:
		return http.StatusOK, nil
	case errors.Is(err, store.ErrIdentityExists):
		return http.StatusConflict, errors.New(codeIdentityExists)
	case errors.Is(err, store.ErrAddressUnproven):
		return http.StatusForbidden, errors.New(codeEmailUnverified)
	case errors.Is(err, store.ErrAccountDisabled):
		return http.StatusForbidden, errAccountDisabled
	case errors.Is(err, store.ErrNotFound):
		return http.StatusBadRequest, errInvalidGrant
	case errors.Is(err, store.ErrUnavailable):
		return http.StatusServiceUnavailable, errProjectDBUnavailable
	default:
		return http.StatusInternalServerError, errors.New("failed to link identity")
	}
}

func (h *AuthHandler) commitLink(ctx context.Context, db store.Store, projectID string, userID int64, claim store.IdentityClaim, clientIP string) (int, error) {
	result, err := db.LinkIdentity(ctx, userID, claim)
	if status, failure := linkFailure(err); failure != nil {
		if status == http.StatusInternalServerError {
			log.Printf("auth.link.failed project=%s userId=%d provider=%s", safeLog(projectID), userID, claim.Provider)
		}
		return status, failure
	}
	for _, squatter := range result.Deleted {
		h.recordAudit(ctx, db, projectID, store.AuditEvent{UserID: squatter, Event: "takeover", Method: claim.Provider, IP: clientIP})
	}
	h.recordAudit(ctx, db, projectID, store.AuditEvent{UserID: userID, Event: "identity_linked", Method: claim.Provider, IP: clientIP})
	if result.Upgraded {
		// The address was just proven by whoever holds the session; there is
		// no earlier owner to warn.
		h.recordAudit(ctx, db, projectID, store.AuditEvent{UserID: userID, Event: "guest_upgraded", Method: claim.Provider, IP: clientIP})
		return http.StatusOK, nil
	}
	h.noticeLinked(ctx, db, projectID, userID, claim.Provider, claim.Email)
	return http.StatusOK, nil
}

// finishAddressLink links an address whose emailed code or link was just
// spent, and starts a session for the account it was linked to.
func (h *AuthHandler) finishAddressLink(w http.ResponseWriter, r *http.Request, db store.Store, otp store.EmailOTP) {
	projectID := projectKey(r)
	claim := store.IdentityClaim{Provider: store.EmailProvider, Subject: store.AddressKey(otp.Email), Email: otp.Email}
	if status, err := h.commitLink(r.Context(), db, projectID, otp.LinkUserID, claim, h.clientIP(r)); err != nil {
		httpError(w, err.Error(), status)
		return
	}
	resp, status, err := h.accountSession(r, db, projectID, otp.LinkUserID, false)
	if err != nil {
		httpError(w, err.Error(), status)
		return
	}
	writeJSON(w, resp)
}

// accountSession starts a session for an account that just proved itself. A
// session after a link does not count as a sign-in, so one fresh sign-in
// cannot be stretched by linking again and again.
func (h *AuthHandler) accountSession(r *http.Request, db store.Store, projectID string, userID int64, signedIn bool) (*domain.AuthResponse, int, error) {
	account, err := db.AccountByID(r.Context(), userID)
	if err != nil {
		return nil, http.StatusBadRequest, errInvalidGrant
	}
	if !account.Enabled {
		return nil, http.StatusForbidden, errAccountDisabled
	}
	roles := accountRoles{role: account.Role, allowed: account.AllowedRoles}
	if err := roles.validate(); err != nil {
		return nil, http.StatusForbidden, err
	}
	_ = db.TouchLastLogin(r.Context(), account.ID)
	user := userInfoOf(account)
	session := h.newRefreshSession(methodOAuth)
	if !signedIn {
		session.AuthTime = time.Time{}
	}
	resp, err := h.startSession(r, projectID, user, roles, account.EmailVerified, session)
	if err != nil {
		return nil, http.StatusInternalServerError, errTokenGeneration
	}
	return resp, http.StatusOK, nil
}

// UnlinkIdentity removes one of the caller's identities unless it is the last
// way the account signs in.
func (h *AuthHandler) UnlinkIdentity(w http.ResponseWriter, r *http.Request) {
	info, ok := h.linkingSettings(w, r)
	if !ok {
		return
	}
	claims, ok := freshEndUser(w, r)
	if !ok {
		return
	}
	identityID, err := strconv.ParseInt(chi.URLParam(r, "identityId"), 10, 64)
	if err != nil || identityID <= 0 {
		httpError(w, codeIdentityNotFound, http.StatusNotFound)
		return
	}
	db, ok := h.storeFor(w, r)
	if !ok || !h.enrolledNeedsAAL2(w, r, info, db, claims) {
		return
	}
	removed, err := db.UnlinkIdentity(r.Context(), claims.UserID, identityID)
	switch {
	case errors.Is(err, store.ErrLastSignInMethod):
		httpError(w, codeLastSignInMethod, http.StatusConflict)
		return
	case err != nil:
		writeStoreFailure(w, err, codeIdentityNotFound)
		return
	}
	h.recordAudit(r.Context(), db, projectKey(r), store.AuditEvent{UserID: claims.UserID, Event: "identity_unlinked",
		Method: removed.Provider, IP: h.clientIP(r)})
	w.WriteHeader(http.StatusNoContent)
}

// writeStoreFailure answers a store error: notFound for a missing row, 503 for
// an unreachable database, 500 otherwise.
func writeStoreFailure(w http.ResponseWriter, err error, notFound string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpError(w, notFound, http.StatusNotFound)
	case errors.Is(err, store.ErrUnavailable):
		httpError(w, errProjectDBUnavailable.Error(), http.StatusServiceUnavailable)
	default:
		httpError(w, "internal error", http.StatusInternalServerError)
	}
}
