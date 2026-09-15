package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/email"
	"github.com/excalibase/auth/internal/token"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// verificationTTL is how long a verification link stays usable.
	verificationTTL = 24 * time.Hour
	// resendVerificationLimit caps verification resends per address per hour.
	resendVerificationLimit  = 3
	resendVerificationWindow = time.Hour
)

var (
	errEmailNotVerified = errors.New("email_not_verified")
	errEmailRequired    = errors.New("email is required")
	errTooManyRequests  = errors.New("too_many_requests")
)

// verifyEmailRequest is the POST body form of the verification link. The GET
// form carries the same token in the query string.
type verifyEmailRequest struct {
	Token string `json:"token"`
}

// projectSettings is the subset of provisioning's project info that shapes the
// verification flow. Lookup failures fall back to the permissive default so a
// control-plane outage never blocks logins.
type projectSettings struct {
	requireEmailVerification bool
	siteURL                  string
}

func (h *AuthHandler) settingsFor(ctx context.Context, projectID string) projectSettings {
	settings := projectSettings{siteURL: h.siteURL}
	info, err := h.poolMgr.GetProjectInfo(ctx, projectID)
	if err != nil {
		return settings
	}
	settings.requireEmailVerification = info.RequireEmailVerification
	if info.SiteURL != "" {
		settings.siteURL = info.SiteURL
	}
	return settings
}

// verificationLink builds the address the user clicks. The token is a query
// parameter, so it must be escaped even though our own alphabet is URL-safe.
func verificationLink(siteURL, plaintext string) string {
	return siteURL + "/verify?token=" + url.QueryEscape(plaintext)
}

// sendVerification mints a fresh single-use token and mails the link. Failures
// are logged and swallowed: a mail outage must not fail a registration that has
// already been committed, and the user can always ask for a resend.
//
// Neither the address nor the token is ever logged.
func (h *AuthHandler) sendVerification(ctx context.Context, db *pgxpool.Pool, projectID string, userID int64, address, siteURL string) {
	plaintext, err := emailVerificationTokens.issue(ctx, db, userID, verificationTTL)
	if err != nil {
		log.Printf("auth.verification.issue_failed project=%s userId=%d", safeLog(projectID), userID)
		return
	}

	msg := email.Message{
		ProjectID: projectID,
		To:        address,
		Template:  email.TemplateVerifyEmail,
		Data: map[string]string{
			"userEmail":   address,
			"verifyUrl":   verificationLink(siteURL, plaintext),
			"expiresHour": strconv.Itoa(int(verificationTTL.Hours())),
		},
	}
	if err := h.emailSender.Send(ctx, msg); err != nil {
		log.Printf("auth.verification.send_failed project=%s userId=%d err=%v", safeLog(projectID), userID, err)
	}
}

// VerifyEmail redeems a verification token. Served on both GET (the link in the
// email) and POST (a front end that posts the token itself).
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	projectID := projectKey(r)

	plaintext := r.URL.Query().Get("token")
	if plaintext == "" && r.Method == http.MethodPost {
		var req verifyEmailRequest
		json.NewDecoder(r.Body).Decode(&req)
		plaintext = req.Token
	}

	db, err := h.poolMgr.GetPool(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		httpError(w, errProjectDBUnavailable.Error(), 503)
		return
	}

	userID, err := emailVerificationTokens.redeem(r.Context(), db, plaintext)
	if err != nil {
		httpError(w, errTokenNotRedeemable.Error(), 400)
		return
	}

	if _, err := db.Exec(r.Context(),
		"UPDATE auth.users SET email_verified = true, updated_at = NOW() WHERE id = $1", userID); err != nil {
		httpError(w, "failed to verify email", 500)
		return
	}

	log.Printf("auth.verification.confirmed project=%s userId=%d", safeLog(projectID), userID)
	writeJSON(w, map[string]interface{}{"verified": true})
}

// ResendVerification re-sends the verification link. It answers 200 for every
// address so it cannot be used to discover which accounts exist, and is capped
// per address so it cannot be used to mail-bomb one.
func (h *AuthHandler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	projectID := projectKey(r)

	var req domain.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "invalid request", 400)
		return
	}
	if req.Email == "" {
		httpError(w, errEmailRequired.Error(), 400)
		return
	}

	// Key on a hash so no address is held in process memory by the limiter.
	if !h.resendThrottle.Allow(token.Hash(projectID + "|" + req.Email)) {
		httpError(w, errTooManyRequests.Error(), 429)
		return
	}

	h.resendVerificationFor(r, projectID, req.Email)
	writeJSON(w, map[string]interface{}{"message": verificationSentMessage})
}

// resendVerificationFor mails a fresh link when the address belongs to an
// existing, still-unverified account. It reports nothing back to the caller:
// every outcome must look identical from outside.
func (h *AuthHandler) resendVerificationFor(r *http.Request, projectID, address string) {
	db, err := h.poolMgr.GetPool(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		return
	}

	var userID int64
	var verified bool
	err = db.QueryRow(r.Context(),
		"SELECT id, email_verified FROM auth.users WHERE email = $1", address,
	).Scan(&userID, &verified)
	if err != nil || verified {
		return
	}

	h.sendVerification(r.Context(), db, projectID, userID, address, h.settingsFor(r.Context(), projectID).siteURL)
}
