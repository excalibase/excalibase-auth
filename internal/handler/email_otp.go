package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/excalibase/auth/internal/email"
	"github.com/excalibase/auth/internal/emailotp"
	"github.com/excalibase/auth/internal/oauth"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/ratelimit"
	"github.com/excalibase/auth/internal/store"
	"github.com/excalibase/auth/internal/token"
	"github.com/go-chi/chi/v5"
)

const (
	// otpTTL is how long an emailed link or code stays usable.
	otpTTL = 10 * time.Minute
	// otpMaxAttempts is how many guesses one code gets. With eight digits and
	// the send budgets no address-wide cap is needed, so none can lock a user out.
	otpMaxAttempts = 5
	otpMailTimeout = 10 * time.Second
	// maxOTPBody bounds both request bodies, which carry a few short fields.
	maxOTPBody = 4 << 10
	// otpSentMessage is the one answer /otp gives every address.
	otpSentMessage = "If the address can sign in, a sign-in email has been sent"
	otpKeyPurpose  = "email-otp v1"
)

// defaultOTPLimits pace the mail: an address once a minute and five times an
// hour, a client fifty times a day, and a project's mailed sends a day, which
// guards the shared sending reputation.
var defaultOTPLimits = store.OTPLimits{MinInterval: time.Minute, PerAddressHour: 5, PerProjectDay: 500, PerIPDay: 50, LinksPerAccountDay: 10}

var codeGuessLimits = store.OTPAttempts{PerCode: otpMaxAttempts}

var (
	errInvalidEmail = errors.New(codeInvalidEmail)
	errOTPType      = errors.New("type must be magiclink or email")
	errOTPKey       = errors.New("email sign-in is unavailable")
)

type otpRequest struct {
	Email               string `json:"email"`
	Type                string `json:"type"`
	CreateUser          *bool  `json:"create_user"`
	RedirectTo          string `json:"redirect_to"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

type verifyOTPRequest struct {
	Type         string `json:"type"`
	Email        string `json:"email"`
	Token        string `json:"token"`
	TokenHash    string `json:"token_hash"`
	CodeVerifier string `json:"code_verifier"`
}

// validAddress accepts a bare address that fits users.email.
func validAddress(raw string) bool {
	if raw == "" || len(raw) > maxEmailLength {
		return false
	}
	parsed, err := mail.ParseAddress(raw)
	return err == nil && parsed.Address == raw
}

func validOTPType(kind string) bool {
	return kind == store.OTPMagicLink || kind == store.OTPEmailCode
}

// emailSignInSettings reads the settings fresh and answers for a project that
// is unreadable (503) or has email sign-in off (404).
func (h *AuthHandler) emailSignInSettings(w http.ResponseWriter, r *http.Request) (pool.ProjectInfo, bool) {
	info, err := h.signInSettings(r.Context(), projectKey(r))
	if err != nil {
		httpError(w, errSettingsUnreadable, http.StatusServiceUnavailable)
		return info, false
	}
	if !info.EmailOTPEnabled {
		httpError(w, codeMethodOff, http.StatusNotFound)
		return info, false
	}
	if h.otpKey == nil {
		httpError(w, errOTPKey.Error(), http.StatusServiceUnavailable)
		return info, false
	}
	return info, true
}

// SendOTP emails a sign-in link or code. Every address gets the same answer;
// only one that can sign in, or may sign up, is mailed.
func (h *AuthHandler) SendOTP(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeOTPRequest(w, r)
	if !ok {
		return
	}
	info, ok := h.emailSignInSettings(w, r)
	if !ok {
		return
	}
	redirectTo := ""
	if req.Type == store.OTPMagicLink {
		if redirectTo, ok = magicLinkTarget(w, req, info); !ok {
			return
		}
	}
	db, ok := h.storeFor(w, r)
	if !ok {
		return
	}
	projectID := projectKey(r)
	createUser := req.CreateUser == nil || *req.CreateUser
	otp, msg, err := h.newEmailOTP(projectID, req, redirectTo, createUser)
	if err != nil {
		httpError(w, "internal error", http.StatusInternalServerError)
		return
	}
	otp.Mailed = h.mayMail(r.Context(), db, req.Email, createUser && info.NewUsersAllowed())
	otp.IP = otpSenderKey(h.clientIP(r))
	h.saveAndMail(w, r, db, projectID, otp, msg)
}

// magicLinkTarget is the allowed page a link lands on, the site URL by default.
func magicLinkTarget(w http.ResponseWriter, req otpRequest, info pool.ProjectInfo) (string, bool) {
	target := req.RedirectTo
	if target == "" {
		target = info.SiteURL
	}
	allowed, ok := oauth.AllowedRedirect(target, allowedRedirects(info))
	if !ok || len(allowed) > maxRedirectLength {
		httpError(w, errRedirectNotAllowed.Error(), http.StatusBadRequest)
		return "", false
	}
	return allowed, true
}

// saveAndMail records the send within the budgets and mails it after the answer.
func (h *AuthHandler) saveAndMail(w http.ResponseWriter, r *http.Request, db store.Store, projectID string, otp store.EmailOTP, msg email.Message) {
	mailed, err := db.SaveEmailOTP(r.Context(), otp, h.otpLimits)
	switch {
	case errors.Is(err, store.ErrRateLimited):
		w.Header().Set("Retry-After", strconv.Itoa(int(h.otpLimits.MinInterval.Seconds())+1))
		httpError(w, codeRateLimited, http.StatusTooManyRequests)
		return
	case err != nil:
		log.Printf("auth.otp.save_failed project=%s", safeLog(projectID))
		httpError(w, "failed to send", http.StatusInternalServerError)
		return
	}
	if mailed {
		h.dispatchMail(func() { h.sendOTPMail(projectID, msg) })
	}
	writeJSON(w, map[string]string{"message": otpSentMessage})
}

func decodeOTPRequest(w http.ResponseWriter, r *http.Request) (otpRequest, bool) {
	var req otpRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxOTPBody)).Decode(&req); err != nil {
		httpError(w, "invalid request", http.StatusBadRequest)
		return req, false
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Type == "" {
		req.Type = store.OTPMagicLink
	}
	switch {
	case !validAddress(req.Email):
		httpError(w, errInvalidEmail.Error(), http.StatusBadRequest)
	case !validOTPType(req.Type):
		httpError(w, errOTPType.Error(), http.StatusBadRequest)
	case req.CodeChallengeMethod != "S256" || !oauth.ValidChallenge(req.CodeChallenge):
		httpError(w, errChallengeRequired.Error(), http.StatusBadRequest)
	default:
		return req, true
	}
	return req, false
}

// newEmailOTP draws the secret and builds both the row and the mail carrying
// it; the plaintext lives only in the mail.
func (h *AuthHandler) newEmailOTP(projectID string, req otpRequest, redirectTo string, createUser bool) (store.EmailOTP, email.Message, error) {
	otp := store.EmailOTP{Email: req.Email, Kind: req.Type, CodeChallenge: req.CodeChallenge,
		CreateUser: createUser, ExpiresAt: time.Now().Add(otpTTL)}
	msg := email.Message{ProjectID: projectID, To: req.Email, Data: map[string]string{
		"userEmail": req.Email, "expiresMin": strconv.Itoa(int(otpTTL.Minutes())),
	}}
	if req.Type == store.OTPMagicLink {
		plaintext, digest, err := token.New()
		if err != nil {
			return otp, msg, err
		}
		otp.LinkHash = digest
		msg.Template = email.TemplateMagicLink
		msg.Data["linkUrl"] = oauth.WithParam(oauth.WithParam(redirectTo, "token_hash", plaintext), "type", store.OTPMagicLink)
		return otp, msg, nil
	}
	code, err := emailotp.NewCode()
	if err != nil {
		return otp, msg, err
	}
	otp.CodeHMAC = emailotp.CodeMAC(h.otpKey, projectID, req.Email, code)
	msg.Template = email.TemplateEmailOTP
	msg.Data["code"] = code
	return otp, msg, nil
}

// mayMail is whether the address reaches an account that can sign in, or may
// become one. Both branches read the database, so their timing is alike.
func (h *AuthHandler) mayMail(ctx context.Context, db store.Store, address string, mayCreate bool) bool {
	account, err := db.AccountByAddress(ctx, address)
	switch {
	case err == nil:
		return account.Enabled
	case errors.Is(err, store.ErrNotFound):
		return mayCreate
	default:
		return false
	}
}

// sendOTPMail runs after the answer, so mail latency tells nothing about the address.
func (h *AuthHandler) sendOTPMail(projectID string, msg email.Message) {
	ctx, cancel := context.WithTimeout(context.Background(), otpMailTimeout)
	defer cancel()
	if err := h.sendMail(ctx, msg); err != nil {
		log.Printf("auth.otp.send_failed project=%s template=%s err=%v", safeLog(projectID), msg.Template, err)
	}
}

// VerifyOTP spends an emailed link or code with the PKCE verifier of the
// browser that asked for it, and starts a session.
func (h *AuthHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	var req verifyOTPRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxOTPBody)).Decode(&req); err != nil || !validVerifyRequest(&req) {
		httpError(w, "invalid request", http.StatusBadRequest)
		return
	}
	info, ok := h.emailSignInSettings(w, r)
	if !ok {
		return
	}
	projectID := projectKey(r)
	db, err := h.poolMgr.GetStore(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		writePoolFailure(w, err)
		return
	}
	otp, err := h.redeemOTP(r.Context(), db, projectID, req)
	if err != nil {
		httpError(w, errTokenNotRedeemable.Error(), http.StatusBadRequest)
		return
	}
	if otp.LinkUserID != 0 {
		h.finishAddressLink(w, r, db, otp)
		return
	}
	account, outcome, status, err := h.signInByEmail(r.Context(), db, projectID, otp, info.NewUsersAllowed())
	if err != nil {
		httpError(w, err.Error(), status)
		return
	}
	_ = db.TouchLastLogin(r.Context(), account.ID)
	h.audit(r.Context(), db, projectID, store.AuditEvent{UserID: account.ID, Method: otp.Kind, IP: h.clientIP(r)}, outcome)
	resp, err := h.generateAuthResponse(r, projectID, userInfoOf(account), accountRoles{role: account.Role, allowed: account.AllowedRoles}, true)
	if err != nil {
		writeSessionFailure(w, err)
		return
	}
	writeJSON(w, resp)
}

func validVerifyRequest(req *verifyOTPRequest) bool {
	req.Email = strings.TrimSpace(req.Email)
	switch req.Type {
	case store.OTPMagicLink:
		return req.TokenHash != "" && req.CodeVerifier != ""
	case store.OTPEmailCode:
		return req.Email != "" && req.Token != "" && req.CodeVerifier != ""
	default:
		return false
	}
}

// redeemOTP checks the secret and the verifier together, both in constant
// time, so a refusal tells neither apart.
func (h *AuthHandler) redeemOTP(ctx context.Context, db store.Store, projectID string, req verifyOTPRequest) (store.EmailOTP, error) {
	if req.Type == store.OTPMagicLink {
		digest := token.Hash(req.TokenHash)
		return db.RedeemEmailOTP(ctx, store.OTPLookup{LinkHash: digest}, codeGuessLimits, func(otp store.EmailOTP) bool {
			linkOK := token.Equal(otp.LinkHash, digest)
			verifierOK := oauth.VerifierMatches(req.CodeVerifier, otp.CodeChallenge)
			return linkOK && verifierOK
		})
	}
	lookup := store.OTPLookup{Email: req.Email, CodeChallenge: oauth.S256(req.CodeVerifier)}
	return db.RedeemEmailOTP(ctx, lookup, codeGuessLimits, func(otp store.EmailOTP) bool {
		codeOK := emailotp.CodeMatches(h.otpKey, projectID, req.Email, req.Token, otp.CodeHMAC)
		verifierOK := oauth.VerifierMatches(req.CodeVerifier, otp.CodeChallenge)
		return codeOK && verifierOK
	})
}

const signInFailedMsg = "sign-in failed"

// signInByEmail reaches the account of a proven address: only a send that
// asked for it, with sign-ups open and budget left, makes a new one.
func (h *AuthHandler) signInByEmail(ctx context.Context, db store.Store, projectID string, otp store.EmailOTP, signupsOpen bool) (store.Account, store.IdentityOutcome, int, error) {
	name := displayName(oauth.Identity{Email: otp.Email})
	account, outcome, err := db.SignInWithEmail(ctx, otp.Email, name, false)
	if errors.Is(err, store.ErrSignupsDisabled) && otp.CreateUser && signupsOpen {
		if h.limits != nil && !h.limits.AllowSignup(projectID) {
			return store.Account{}, 0, http.StatusTooManyRequests, errors.New(codeRateLimited)
		}
		if err := h.allowNewUser(ctx, projectID, newUser{Method: "email", Email: otp.Email}); err != nil {
			status, refusal := sessionFailure(err)
			return store.Account{}, 0, status, refusal
		}
		account, outcome, err = db.SignInWithEmail(ctx, otp.Email, name, true)
	}
	switch {
	case errors.Is(err, store.ErrSignupsDisabled):
		return store.Account{}, 0, http.StatusForbidden, errSignupDisabled
	case errors.Is(err, store.ErrAccountDisabled):
		return store.Account{}, 0, http.StatusForbidden, errAccountDisabled
	case errors.Is(err, store.ErrAmbiguousEmail):
		return store.Account{}, 0, http.StatusConflict, errors.New(signInFailedMsg)
	case errors.Is(err, store.ErrUnavailable):
		return store.Account{}, 0, http.StatusServiceUnavailable, errProjectDBUnavailable
	case err != nil:
		log.Printf("auth.otp.account_failed project=%s", safeLog(projectID))
		return store.Account{}, 0, http.StatusInternalServerError, errors.New(signInFailedMsg)
	case !account.Enabled:
		return store.Account{}, 0, http.StatusForbidden, errAccountDisabled
	}
	if err := (accountRoles{role: account.Role, allowed: account.AllowedRoles}).validate(); err != nil {
		return store.Account{}, 0, http.StatusForbidden, err
	}
	return account, outcome, http.StatusOK, nil
}

// auditEvents names each way a sign-in reached its account.
var auditEvents = map[store.IdentityOutcome]string{
	store.IdentityCreated:  "sign_up",
	store.IdentityTookOver: "takeover",
}

// audit records a sign-in.
func (h *AuthHandler) audit(ctx context.Context, db store.Store, projectID string, event store.AuditEvent, outcome store.IdentityOutcome) {
	name, ok := auditEvents[outcome]
	if !ok {
		name = "sign_in"
	}
	event.Event = name
	h.recordAudit(ctx, db, projectID, event)
}

// recordAudit writes an audit row; a failure to write it is logged, never the action's.
func (h *AuthHandler) recordAudit(ctx context.Context, db store.Store, projectID string, event store.AuditEvent) {
	if err := db.RecordAudit(ctx, event); err != nil {
		log.Printf("auth.audit.write_failed project=%s event=%s", safeLog(projectID), event.Event)
	}
}

// otpSenderKey is the client a send budget is kept for: an IPv4 address, or
// an IPv6 /64, which one subscriber usually holds whole.
func otpSenderKey(ip string) string {
	parsed := net.ParseIP(ip)
	switch {
	case parsed == nil:
		return ip
	case parsed.To4() != nil:
		return parsed.To4().String()
	default:
		prefix := net.CIDRMask(64, 128)
		return (&net.IPNet{IP: parsed.Mask(prefix), Mask: prefix}).String()
	}
}

func (h *AuthHandler) clientIP(r *http.Request) string {
	return ratelimit.ClientIP(r, h.trustedProxies)
}
