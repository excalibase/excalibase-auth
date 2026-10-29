package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/store"
)

const (
	codeCaptchaRequired    = "captcha_required"
	codeCaptchaFailed      = "captcha_failed"
	codeCaptchaUnavailable = "captcha_unavailable"

	turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	captchaTimeout     = 5 * time.Second
	// maxCaptchaToken is above Turnstile's 2048-character tokens.
	maxCaptchaToken = 4096
	maxGuestBody    = 8 << 10

	// DefaultGuestInactiveDays is how long a guest may go without signing in
	// or refreshing before the sweeper deletes it.
	DefaultGuestInactiveDays = 30
	// guestSweepEvery is how often one replica may sweep a project; the claim
	// in the project's database keeps the others out.
	guestSweepEvery = 24 * time.Hour
	// guestSweepBatch bounds the deletions of one sweep of one project.
	guestSweepBatch = 10000
)

// defaultGuestLimits pace guest sign-ups: thirty an hour per client (an IPv4
// address or an IPv6 /64) and a thousand a day per project.
var defaultGuestLimits = store.GuestLimits{PerClientHour: 30, PerProjectDay: 1000}

type guestRequest struct {
	CaptchaToken string `json:"captchaToken"`
}

// WithGuestInactivity sets how long an unused guest is kept; days below one keep the default.
func (h *AuthHandler) WithGuestInactivity(days int) *AuthHandler {
	if days >= 1 {
		h.guestInactiveAfter = time.Duration(days) * 24 * time.Hour
	}
	return h
}

// SignInAsGuest makes an account with no address and starts its session.
func (h *AuthHandler) SignInAsGuest(w http.ResponseWriter, r *http.Request) {
	info, ok := h.guestSettings(w, r)
	if !ok {
		return
	}
	req, ok := decodeGuestRequest(w, r)
	if !ok {
		return
	}
	projectID := projectKey(r)
	if info.GuestCaptchaEnabled && !h.captchaPassed(w, r, projectID, req.CaptchaToken) {
		return
	}
	db, ok := h.storeFor(w, r)
	if !ok {
		return
	}
	clientIP := h.clientIP(r)
	account, err := db.CreateGuest(r.Context(), otpSenderKey(clientIP), h.guestLimits)
	switch {
	case errors.Is(err, store.ErrRateLimited):
		w.Header().Set("Retry-After", strconv.Itoa(int(time.Hour.Seconds())))
		httpError(w, codeRateLimited, http.StatusTooManyRequests)
		return
	case err != nil:
		writeStoreFailure(w, err, "failed to create guest")
		return
	}
	h.recordAudit(r.Context(), db, projectID, store.AuditEvent{UserID: account.ID, Event: "sign_up", Method: "guest", IP: clientIP})
	resp, err := h.generateAuthResponse(r, projectID, userInfoOf(account), accountRoles{role: account.Role, allowed: account.AllowedRoles}, false)
	if err != nil {
		httpError(w, errTokenGeneration.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, resp)
}

// decodeGuestRequest accepts an empty body as no captcha token.
func decodeGuestRequest(w http.ResponseWriter, r *http.Request) (guestRequest, bool) {
	var req guestRequest
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGuestBody)).Decode(&req)
	if err != nil && !errors.Is(err, io.EOF) {
		httpError(w, codeInvalidRequest, http.StatusBadRequest)
		return req, false
	}
	if len(req.CaptchaToken) > maxCaptchaToken {
		httpError(w, codeCaptchaFailed, http.StatusBadRequest)
		return req, false
	}
	return req, true
}

// guestSettings reads the settings fresh: 503 when unreadable, 404 while
// guests are off for the project, 403 while it takes no new accounts.
func (h *AuthHandler) guestSettings(w http.ResponseWriter, r *http.Request) (pool.ProjectInfo, bool) {
	info, err := h.signInSettings(r.Context(), projectKey(r))
	switch {
	case err != nil:
		httpError(w, errSettingsUnreadable, http.StatusServiceUnavailable)
	case !info.GuestSignInOn():
		httpError(w, codeMethodOff, http.StatusNotFound)
	case !info.NewUsersAllowed():
		httpError(w, errSignupDisabled.Error(), http.StatusForbidden)
	default:
		return info, true
	}
	return info, false
}

// captchaPassed checks the token with Turnstile; anything short of its yes refuses.
func (h *AuthHandler) captchaPassed(w http.ResponseWriter, r *http.Request, projectID, captchaToken string) bool {
	if captchaToken == "" {
		httpError(w, codeCaptchaRequired, http.StatusBadRequest)
		return false
	}
	secret, err := h.poolMgr.CaptchaSecret(r.Context(), projectID)
	if err != nil {
		log.Printf("auth.guest.captcha_secret_unavailable project=%s", safeLog(projectID))
		httpError(w, codeCaptchaUnavailable, http.StatusServiceUnavailable)
		return false
	}
	passed, err := h.verifyCaptcha(r.Context(), secret, captchaToken, h.clientIP(r))
	switch {
	case err != nil:
		log.Printf("auth.guest.captcha_unreachable project=%s err=%v", safeLog(projectID), err)
		httpError(w, codeCaptchaUnavailable, http.StatusServiceUnavailable)
		return false
	case !passed:
		httpError(w, codeCaptchaFailed, http.StatusBadRequest)
		return false
	}
	return true
}

func (h *AuthHandler) verifyCaptcha(ctx context.Context, secret, captchaToken, clientIP string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, captchaTimeout)
	defer cancel()
	form := url.Values{"secret": {secret}, "response": {captchaToken}}
	if clientIP != "" {
		form.Set("remoteip", clientIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.captchaVerifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.oauthHTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, errors.New("captcha verify returned " + strconv.Itoa(resp.StatusCode))
	}
	var answer struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&answer); err != nil {
		return false, err
	}
	return answer.Success, nil
}

// guestRefreshAllowed lets a guest's session go on while the control plane's
// flag is on, whatever the project's own switch says.
func (h *AuthHandler) guestRefreshAllowed(ctx context.Context, projectID string) error {
	info, err := h.signInSettings(ctx, projectID)
	if err != nil {
		return refreshRefusal{status: http.StatusServiceUnavailable, err: errors.New(errSettingsUnreadable)}
	}
	if !info.GuestsOn() {
		return refreshRefusal{status: http.StatusForbidden, err: errors.New(codeMethodOff)}
	}
	return nil
}

// userInfoOf is the user a session answers with.
func userInfoOf(account store.Account) domain.UserInfo {
	return domain.UserInfo{ID: account.ID, Email: account.Email, FullName: account.FullName, IsGuest: account.IsGuest}
}

// StartGuestSweeper sweeps every hour until ctx ends; each project is swept
// at most once a day.
func (h *AuthHandler) StartGuestSweeper(ctx context.Context, every time.Duration) {
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.SweepGuests(ctx)
			}
		}
	}()
}

// SweepGuests deletes the inactive guests of the projects this replica has a
// pool for, only while the control plane's guest flag is on for them.
func (h *AuthHandler) SweepGuests(ctx context.Context) {
	for projectID, db := range h.poolMgr.OpenStores() {
		h.sweepProject(ctx, projectID, db)
	}
}

func (h *AuthHandler) sweepProject(ctx context.Context, projectID string, db store.Store) {
	info, err := h.signInSettings(ctx, projectID)
	if err != nil || !info.GuestsOn() {
		return
	}
	claimed, err := db.ClaimGuestCleanup(ctx, guestSweepEvery)
	if err != nil || !claimed {
		return
	}
	deleted, err := db.DeleteInactiveGuests(ctx, time.Now().Add(-h.guestInactiveAfter), guestSweepBatch)
	if err != nil {
		log.Printf("auth.guest.sweep_failed project=%s deleted=%d err=%v", safeLog(projectID), deleted, err)
		return
	}
	if deleted > 0 {
		log.Printf("auth.guest.swept project=%s deleted=%d", safeLog(projectID), deleted)
	}
}
