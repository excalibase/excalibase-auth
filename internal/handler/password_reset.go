package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/email"
	"github.com/excalibase/auth/internal/token"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// resetTTL keeps a reset link usable for an hour — long enough to reach the
	// inbox, short enough that a leaked link mostly ages out on its own.
	resetTTL = time.Hour
	// forgotPasswordLimit caps reset requests per hour, counted separately per
	// address and per client IP.
	forgotPasswordLimit  = 3
	forgotPasswordWindow = time.Hour
	// resetSentMessage is the single answer /forgot-password gives every caller.
	resetSentMessage = "If the account exists, a password reset email has been sent"
)

var (
	errPasswordRequired = errors.New("newPassword is required")
	errResetTokenNeeded = errors.New("token is required")
)

type forgotPasswordRequest struct {
	Email string `json:"email"`
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

// validatePassword holds the one password policy both registration and reset
// answer to. It is deliberately a single function so tightening the rule can
// never leave one of the two doors more permissive than the other.
func validatePassword(password string) error {
	if password == "" {
		return errPasswordRequired
	}
	return nil
}

// clientIP returns the caller's address for rate-limiting purposes, preferring
// the first hop in X-Forwarded-For when the service runs behind a proxy.
func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		first, _, _ := strings.Cut(forwarded, ",")
		if first = strings.TrimSpace(first); first != "" {
			return first
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func resetLink(siteURL, plaintext string) string {
	return siteURL + "/reset-password?token=" + url.QueryEscape(plaintext)
}

// ForgotPassword starts a password reset. It answers 200 for every address —
// existing or not, verified or not — so it reveals nothing about who has an
// account, and it is capped per address and per client IP so it can be used
// neither to mail-bomb one inbox nor to sweep many.
func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	projectID := projectKey(r)

	var req forgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "invalid request", 400)
		return
	}
	if req.Email == "" {
		httpError(w, errEmailRequired.Error(), 400)
		return
	}

	// Counted before the lookup so throttling behaves identically for addresses
	// that exist and addresses that don't.
	addressKey := token.Hash(projectID + "|" + req.Email)
	ipKey := token.Hash(projectID + "|ip|" + clientIP(r))
	if !h.forgotThrottle.Allow(addressKey) || !h.forgotThrottle.Allow(ipKey) {
		httpError(w, errTooManyRequests.Error(), 429)
		return
	}

	h.sendPasswordReset(r, projectID, req.Email)
	writeJSON(w, map[string]interface{}{"message": resetSentMessage})
}

// sendPasswordReset mails a reset link when the address belongs to a real
// account. It reports nothing back: every outcome must look the same outside.
func (h *AuthHandler) sendPasswordReset(r *http.Request, projectID, address string) {
	db, err := h.poolMgr.GetPool(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		return
	}

	var userID int64
	if err := db.QueryRow(r.Context(),
		"SELECT id FROM auth.users WHERE email = $1", address).Scan(&userID); err != nil {
		return
	}

	// issue invalidates anything outstanding, so the newest link is the only
	// live one and an older leaked link stops working.
	plaintext, err := passwordResetTokens.issue(r.Context(), db, userID, resetTTL)
	if err != nil {
		log.Printf("auth.reset.issue_failed project=%s userId=%d", safeLog(projectID), userID)
		return
	}

	msg := email.Message{
		ProjectID: projectID,
		To:        address,
		Template:  email.TemplatePasswordReset,
		Data: map[string]string{
			"userEmail":  address,
			"resetUrl":   resetLink(h.settingsFor(r.Context(), projectID).siteURL, plaintext),
			"expiresMin": strconv.Itoa(int(resetTTL.Minutes())),
		},
	}
	if err := h.emailSender.Send(r.Context(), msg); err != nil {
		log.Printf("auth.reset.send_failed project=%s userId=%d err=%v", safeLog(projectID), userID, err)
	}
}

// ResetPassword redeems a reset token and sets a new password. Every session
// the account had is revoked: a reset is the remedy for a compromised account,
// so it has to end whatever access an attacker already holds.
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	projectID := projectKey(r)

	var req resetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "invalid request", 400)
		return
	}
	if req.Token == "" {
		httpError(w, errResetTokenNeeded.Error(), 400)
		return
	}
	// Checked before the token is redeemed so a rejected password does not
	// burn the user's only link.
	if err := validatePassword(req.NewPassword); err != nil {
		httpError(w, err.Error(), 400)
		return
	}

	db, err := h.poolMgr.GetPool(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		httpError(w, errProjectDBUnavailable.Error(), 503)
		return
	}

	userID, err := passwordResetTokens.redeem(r.Context(), db, req.Token)
	if err != nil {
		httpError(w, errTokenNotRedeemable.Error(), 400)
		return
	}

	if err := applyNewPassword(r.Context(), db, userID, req.NewPassword); err != nil {
		httpError(w, "failed to reset password", 500)
		return
	}

	log.Printf("auth.reset.completed project=%s userId=%d", safeLog(projectID), userID)
	writeJSON(w, map[string]interface{}{"message": "Password has been reset"})
}

// applyNewPassword stores the new credential and revokes every refresh token
// the account holds.
func applyNewPassword(ctx context.Context, db *pgxpool.Pool, userID int64, password string) error {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	if _, err := db.Exec(ctx,
		"UPDATE auth.users SET password = $1, updated_at = NOW() WHERE id = $2", hash, userID); err != nil {
		return err
	}
	_, err = db.Exec(ctx,
		"UPDATE auth.refresh_tokens SET revoked = true WHERE user_id = $1 AND revoked = false", userID)
	return err
}
