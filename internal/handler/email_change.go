package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/excalibase/auth/internal/email"
	"github.com/excalibase/auth/internal/oauth"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/store"
	"github.com/excalibase/auth/internal/token"
)

const (
	// emailChangeTTL is how long the link to the new address stays usable.
	emailChangeTTL  = time.Hour
	emailChangeType = "email_change"
	codeEmailExists = "email_exists"
)

// defaultEmailChangeLimits pace an account's changes to one a minute and five
// a day, and bound a project's mailed changes a day like its sign-in mail.
var defaultEmailChangeLimits = store.EmailChangeLimits{MinInterval: time.Minute, PerAccountDay: 5, PerProjectDay: 500}

// emailChangeTarget is the allowed page the link lands on, the site URL by default.
func emailChangeTarget(w http.ResponseWriter, requested string, info pool.ProjectInfo) (string, bool) {
	target := requested
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

// requestEmailChange records the request and, unless the address is taken or
// the budget spent, mails the link to it and a notice to the current address.
// The answer is the same either way.
func (h *AuthHandler) requestEmailChange(w http.ResponseWriter, r *http.Request, db store.Store, account store.Account, newEmail, redirectTo string) bool {
	plaintext, digest, err := token.New()
	if err != nil {
		httpError(w, "internal error", http.StatusInternalServerError)
		return false
	}
	mailed, err := db.SaveEmailChange(r.Context(), store.EmailChange{UserID: account.ID, NewEmail: newEmail,
		TokenHash: digest, ExpiresAt: time.Now().Add(emailChangeTTL)}, h.emailChangeLimits)
	if errors.Is(err, store.ErrRateLimited) {
		w.Header().Set("Retry-After", strconv.Itoa(int(h.emailChangeLimits.MinInterval.Seconds())+1))
		httpError(w, codeRateLimited, http.StatusTooManyRequests)
		return false
	}
	if status, failure := linkFailure(err); failure != nil {
		httpError(w, failure.Error(), status)
		return false
	}
	projectID := projectKey(r)
	h.recordAudit(r.Context(), db, projectID, store.AuditEvent{UserID: account.ID, Event: "email_change_requested", IP: h.clientIP(r)})
	if mailed {
		link := oauth.WithParam(oauth.WithParam(redirectTo, "token_hash", plaintext), "type", emailChangeType)
		h.dispatchMail(func() { h.mailEmailChange(projectID, account.Email, newEmail, link) })
	}
	return true
}

func (h *AuthHandler) mailEmailChange(projectID, oldEmail, newEmail, link string) {
	expires := strconv.Itoa(int(emailChangeTTL.Minutes()))
	h.sendOTPMail(projectID, email.Message{ProjectID: projectID, To: newEmail, Template: email.TemplateEmailChange,
		Data: map[string]string{"userEmail": newEmail, "linkUrl": link, "expiresMin": expires}})
	h.sendOTPMail(projectID, email.Message{ProjectID: projectID, To: oldEmail, Template: email.TemplateEmailChangeNotice,
		Data: map[string]string{"userEmail": oldEmail, "newEmail": newEmail}})
}

type confirmEmailChangeRequest struct {
	TokenHash string `json:"token_hash"`
}

// ConfirmEmailChange spends the link mailed to the new address and moves the
// account to it. The link proves the inbox; the request it answers needed a
// recent sign-in, so no session is asked for here and none is handed out.
func (h *AuthHandler) ConfirmEmailChange(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.userAPISettings(w, r); !ok {
		return
	}
	var req confirmEmailChangeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxOTPBody)).Decode(&req); err != nil || req.TokenHash == "" {
		httpError(w, codeInvalidRequest, http.StatusBadRequest)
		return
	}
	db, ok := h.storeFor(w, r)
	if !ok {
		return
	}
	changed, err := db.ConfirmEmailChange(r.Context(), token.Hash(req.TokenHash))
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpError(w, errTokenNotRedeemable.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, store.ErrIdentityExists):
		httpError(w, codeEmailExists, http.StatusConflict)
		return
	case err != nil:
		status, failure := linkFailure(err)
		httpError(w, failure.Error(), status)
		return
	}
	h.recordEmailChange(r.Context(), db, projectKey(r), changed, h.clientIP(r))
	writeJSON(w, map[string]string{"message": "Email address changed"})
}

func (h *AuthHandler) recordEmailChange(ctx context.Context, db store.Store, projectID string, changed store.ChangedEmail, clientIP string) {
	for _, replaced := range changed.Replaced {
		h.recordAudit(ctx, db, projectID, store.AuditEvent{UserID: replaced, Event: "takeover", Method: store.EmailProvider, IP: clientIP})
	}
	h.recordAudit(ctx, db, projectID, store.AuditEvent{UserID: changed.UserID, Event: "email_changed", IP: clientIP})
	log.Printf("auth.user.email_changed project=%s userId=%d", safeLog(projectID), changed.UserID)
}
