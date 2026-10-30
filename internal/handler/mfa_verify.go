package handler

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/mfa"
	"github.com/excalibase/auth/internal/middleware"
	"github.com/excalibase/auth/internal/store"
	"github.com/excalibase/auth/internal/token"
	"github.com/go-chi/chi/v5"
)

// mfaFailureRetry is what a locked caller is told to wait, the failure window.
const mfaFailureRetry = 5 * time.Minute

type verifyFactorRequest struct {
	ChallengeID  string `json:"challengeId"`
	Code         string `json:"code"`
	RefreshToken string `json:"refreshToken"`
}

type recoveryRequest struct {
	Code         string `json:"code"`
	RefreshToken string `json:"refreshToken"`
}

// elevatedSession is an aal2 session, with the recovery codes of an account
// that just turned MFA on.
type elevatedSession struct {
	*domain.AuthResponse
	RecoveryCodes []string `json:"recoveryCodes,omitempty"`
}

// stepUpSession is the caller's account and refresh token, checked before any
// code is spent: the token must be live and the caller's, the account allowed on.
type stepUpSession struct {
	account   store.Account
	roles     accountRoles
	presented string
}

func (h *AuthHandler) stepUpSession(w http.ResponseWriter, r *http.Request, db store.Store, refreshToken string) (stepUpSession, bool) {
	claims := middleware.ClaimsFromContext(r.Context())
	if refreshToken == "" {
		httpError(w, errInvalidRefreshToken.Error(), http.StatusUnauthorized)
		return stepUpSession{}, false
	}
	presented := token.Hash(refreshToken)
	state, err := db.RefreshTokenState(r.Context(), presented)
	switch {
	case errors.Is(err, store.ErrUnavailable):
		httpError(w, errProjectDBUnavailable.Error(), http.StatusServiceUnavailable)
		return stepUpSession{}, false
	case err != nil || state.UserID != claims.UserID:
		httpError(w, errInvalidRefreshToken.Error(), http.StatusUnauthorized)
		return stepUpSession{}, false
	case state.Revoked:
		// A spent token presented again leaked, as on /refresh: its session ends.
		status, refusal := rejectDeadRefreshToken(r.Context(), db, presented)
		httpError(w, refusal.Error(), status)
		return stepUpSession{}, false
	}
	account, err := db.AccountByID(r.Context(), claims.UserID)
	if err != nil {
		writeStoreFailure(w, err, errUserNotFound.Error())
		return stepUpSession{}, false
	}
	roles, err := h.refreshAllowed(r.Context(), projectKey(r), account)
	var refusal refreshRefusal
	switch {
	case errors.As(err, &refusal):
		httpError(w, refusal.err.Error(), refusal.status)
		return stepUpSession{}, false
	case err != nil:
		httpError(w, errSettingsUnreadable, http.StatusServiceUnavailable)
		return stepUpSession{}, false
	}
	return stepUpSession{account: account, roles: roles, presented: presented}, true
}

// VerifyFactor checks a TOTP code against a live challenge and moves the
// caller's session to aal2. The first verified factor also gets recovery codes.
func (h *AuthHandler) VerifyFactor(w http.ResponseWriter, r *http.Request) {
	var req verifyFactorRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxFactorBody)).Decode(&req); err != nil || req.ChallengeID == "" || req.Code == "" {
		httpError(w, codeInvalidRequest, http.StatusBadRequest)
		return
	}
	db, ok := h.storeFor(w, r)
	if !ok {
		return
	}
	session, ok := h.stepUpSession(w, r, db, req.RefreshToken)
	if !ok {
		return
	}
	keys, ok := h.mfaKeys(w, r)
	if !ok {
		return
	}
	userID, factorID := session.account.ID, chi.URLParam(r, "factorId")
	attempt := store.FactorAttempt{UserID: userID, FactorID: factorID, ChallengeID: req.ChallengeID,
		CallerAAL2: atAAL2(middleware.ClaimsFromContext(r.Context()))}
	verified, err := db.VerifyFactor(r.Context(), attempt,
		h.mfaLimits, func(factor store.FactorSecret) (int64, bool, error) {
			secret, err := keys.Open(factor.SecretSealed, userID, factor.ID)
			if err != nil {
				return 0, false, err
			}
			step, matched := mfa.Match(secret, req.Code, time.Now(), factor.LastUsedStep)
			return step, matched, nil
		})
	if !h.writeCodeFailure(w, r, db, userID, methodTOTP, err) {
		return
	}
	// Codes are issued once the session is elevated, so they are never stored unseen.
	h.finishStepUp(w, r, db, session, methodTOTP, func() []string {
		if !verified.FirstForAccount {
			return nil
		}
		return h.issueRecoveryCodes(r, db, keys, userID)
	})
}

// writeCodeFailure answers a refused code and audits it; true when there was none.
func (h *AuthHandler) writeCodeFailure(w http.ResponseWriter, r *http.Request, db store.Store, userID int64, method string, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, store.ErrInvalidCode):
		h.recordAudit(r.Context(), db, projectKey(r), store.AuditEvent{UserID: userID, Event: "mfa_failed", Method: method, IP: h.clientIP(r)})
		httpError(w, codeInvalidCode, http.StatusBadRequest)
	case errors.Is(err, store.ErrTooManyAttempts):
		w.Header().Set("Retry-After", strconv.Itoa(int(mfaFailureRetry.Seconds())))
		httpError(w, codeTooManyAttempts, http.StatusTooManyRequests)
	case errors.Is(err, store.ErrInsufficientAAL):
		httpError(w, codeInsufficientAAL, http.StatusForbidden)
	case errors.Is(err, store.ErrInvalidChallenge):
		httpError(w, codeInvalidChallenge, http.StatusBadRequest)
	case errors.Is(err, store.ErrNotFound):
		httpError(w, codeFactorNotFound, http.StatusNotFound)
	case errors.Is(err, store.ErrUnavailable):
		httpError(w, errProjectDBUnavailable.Error(), http.StatusServiceUnavailable)
	default:
		log.Printf("auth.mfa.check_failed project=%s userId=%d: %v", safeLog(projectKey(r)), userID, err)
		httpError(w, codeMFAUnavailable, http.StatusServiceUnavailable)
	}
	return false
}

// issueRecoveryCodes stores a new set and returns it; a failure leaves the
// account to regenerate them from its aal2 session.
func (h *AuthHandler) issueRecoveryCodes(r *http.Request, db store.Store, keys mfa.Keys, userID int64) []string {
	codes, err := mfa.NewRecoveryCodes(mfa.RecoveryCodeCount)
	if err != nil {
		log.Printf("auth.mfa.recovery_codes_failed project=%s userId=%d: %v", safeLog(projectKey(r)), userID, err)
		return nil
	}
	hashes := make([]string, 0, len(codes))
	for _, code := range codes {
		// Generated codes are always well formed.
		hash, _ := keys.HashRecoveryCode(code)
		hashes = append(hashes, hash)
	}
	if err := db.ReplaceRecoveryCodes(r.Context(), userID, hashes); err != nil {
		log.Printf("auth.mfa.recovery_codes_failed project=%s userId=%d", safeLog(projectKey(r)), userID)
		return nil
	}
	return codes
}

// finishStepUp spends the presented refresh token into an aal2 successor in
// the same session and answers it.
func (h *AuthHandler) finishStepUp(w http.ResponseWriter, r *http.Request, db store.Store, session stepUpSession, method string, recoveryCodes func() []string) {
	successor, successorHash, err := token.New()
	if err != nil {
		httpError(w, errRefreshTokenStore.Error(), http.StatusInternalServerError)
		return
	}
	account, elevated, err := db.ElevateRefreshToken(r.Context(), session.account.ID, session.presented, successorHash, method)
	if err != nil {
		writeElevateFailure(w, err)
		return
	}
	h.recordAudit(r.Context(), db, projectKey(r), store.AuditEvent{UserID: account.ID, Event: "mfa_verified", Method: method, IP: h.clientIP(r)})
	var codes []string
	if recoveryCodes != nil {
		codes = recoveryCodes()
	}
	resp, err := h.sessionResponse(r, projectKey(r), userInfoOf(account), session.roles, account.EmailVerified, successor, elevated)
	if err != nil {
		httpError(w, errTokenGeneration.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, elevatedSession{AuthResponse: resp, RecoveryCodes: codes})
}

func writeElevateFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrNoAccount):
		httpError(w, errInvalidRefreshToken.Error(), http.StatusUnauthorized)
	case errors.Is(err, store.ErrUnavailable):
		httpError(w, errProjectDBUnavailable.Error(), http.StatusServiceUnavailable)
	default:
		httpError(w, errRefreshTokenStore.Error(), http.StatusInternalServerError)
	}
}

// unmatchableHash stands in for typed text that cannot be a code, so it is
// refused and counted like a wrong code.
const unmatchableHash = "-"

// RecoverWithCode spends one recovery code and moves the caller's session to aal2.
func (h *AuthHandler) RecoverWithCode(w http.ResponseWriter, r *http.Request) {
	var req recoveryRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxFactorBody)).Decode(&req); err != nil || req.Code == "" {
		httpError(w, codeInvalidRequest, http.StatusBadRequest)
		return
	}
	db, ok := h.storeFor(w, r)
	if !ok {
		return
	}
	session, ok := h.stepUpSession(w, r, db, req.RefreshToken)
	if !ok {
		return
	}
	keys, ok := h.mfaKeys(w, r)
	if !ok {
		return
	}
	hash, wellFormed := keys.HashRecoveryCode(req.Code)
	if !wellFormed {
		hash = unmatchableHash
	}
	err := db.RedeemRecoveryCode(r.Context(), session.account.ID, hash, h.mfaLimits)
	if !h.writeCodeFailure(w, r, db, session.account.ID, methodRecovery, err) {
		return
	}
	h.finishStepUp(w, r, db, session, methodRecovery, nil)
}

// RegenerateRecoveryCodes replaces the caller's set; it takes an aal2 session.
func (h *AuthHandler) RegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if !atAAL2(claims) {
		httpError(w, codeInsufficientAAL, http.StatusForbidden)
		return
	}
	db, ok := h.storeFor(w, r)
	if !ok {
		return
	}
	enrolled, err := db.HasVerifiedFactor(r.Context(), claims.UserID)
	if err != nil {
		writeStoreFailure(w, err, errUserNotFound.Error())
		return
	}
	if !enrolled {
		httpError(w, codeNoVerifiedFactor, http.StatusConflict)
		return
	}
	keys, ok := h.mfaKeys(w, r)
	if !ok {
		return
	}
	codes := h.issueRecoveryCodes(r, db, keys, claims.UserID)
	if codes == nil {
		httpError(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.recordAudit(r.Context(), db, projectKey(r), store.AuditEvent{UserID: claims.UserID, Event: "mfa_codes_renewed", Method: methodRecovery, IP: h.clientIP(r)})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string][]string{"recoveryCodes": codes})
}

// ResetUserMFA is the project's way back in for an end user who lost every
// factor and code: it removes them all and ends the account's sessions.
func (h *AuthHandler) ResetUserMFA(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(chi.URLParam(r, "userId"), 10, 64)
	if err != nil || userID <= 0 {
		httpError(w, errUserNotFound.Error(), http.StatusNotFound)
		return
	}
	db, ok := h.storeFor(w, r)
	if !ok {
		return
	}
	if err := db.ResetMFA(r.Context(), userID); err != nil {
		writeStoreFailure(w, err, errUserNotFound.Error())
		return
	}
	actor, _ := userManagerActor(middleware.ClaimsFromContext(r.Context()), projectKey(r))
	h.recordAudit(r.Context(), db, projectKey(r), store.AuditEvent{UserID: userID, Event: "mfa_reset", Method: "admin", IP: h.clientIP(r)})
	log.Printf("auth.mfa.reset project=%s userId=%d actor=%s", safeLog(projectKey(r)), userID, safeLog(actor))
	w.WriteHeader(http.StatusNoContent)
}
