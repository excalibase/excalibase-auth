package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/mfa"
	"github.com/excalibase/auth/internal/middleware"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	codeInsufficientAAL  = "insufficient_aal"
	codeInvalidCode      = "invalid_code"
	codeInvalidChallenge = "invalid_challenge"
	codeTooManyAttempts  = "too_many_attempts"
	codeFactorNotFound   = "factor_not_found"
	codeTooManyFactors   = "too_many_factors"
	codeFactorNameTaken  = "factor_name_taken"
	codeNoVerifiedFactor = "no_verified_factor"
	codeMFAUnavailable   = "mfa_unavailable"

	maxFactorBody    = 4 << 10
	maxFriendlyName  = 100
	maxIssuer        = 100
	mfaChallengeTTL  = 5 * time.Minute
	defaultFactorTag = "Authenticator"
)

var defaultMFALimits = store.MFALimits{MaxFactors: 10, MaxFailures: 5, FailureWindow: 5 * time.Minute,
	MaxDailyFailures: 20, StaleUnverified: 24 * time.Hour}

// mfaRoutes mounts /factors (EXC-662); a project without MFA answers 404.
func (h *AuthHandler) mfaRoutes(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(h.requireMFA, middleware.RequireJWT(h.jwtService), requireEndUser)
		r.Route("/factors", h.FactorRoutes)
	})
}

// FactorRoutes are a signed-in end user's second factors. Routes mounts them
// behind the MFA switch, RequireJWT and requireEndUser.
func (h *AuthHandler) FactorRoutes(r chi.Router) {
	r.Use(requireAccountHolder)
	r.Get("/", h.ListFactors)
	r.With(h.limit(rateLimitToken)).Post("/", h.EnrollFactor)
	r.With(h.limit(rateLimitToken)).Post("/recovery", h.RecoverWithCode)
	r.With(h.limit(rateLimitToken)).Post("/recovery-codes", h.RegenerateRecoveryCodes)
	r.With(h.limit(rateLimitToken)).Post("/{factorId}/challenge", h.ChallengeFactor)
	r.With(h.limit(rateLimitToken)).Post("/{factorId}/verify", h.VerifyFactor)
	r.With(h.limit(rateLimitToken)).Delete("/{factorId}", h.UnenrollFactor)
}

// mfaSettings reads the settings fresh: 503 when unreadable, 404 while MFA is off.
func (h *AuthHandler) mfaSettings(w http.ResponseWriter, r *http.Request) (pool.ProjectInfo, bool) {
	info, err := h.signInSettings(r.Context(), projectKey(r))
	if err != nil {
		httpError(w, errSettingsUnreadable, http.StatusServiceUnavailable)
		return info, false
	}
	if !info.MFAEnabled {
		httpError(w, codeMethodOff, http.StatusNotFound)
		return info, false
	}
	return info, true
}

// requireMFA answers before anything else is read while MFA is off.
func (h *AuthHandler) requireMFA(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := h.mfaSettings(w, r); ok {
			next.ServeHTTP(w, r)
		}
	})
}

// requireAccountHolder refuses a guest: it has no address to recover through.
func requireAccountHolder(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if claims := middleware.ClaimsFromContext(r.Context()); claims.IsGuest != nil && *claims.IsGuest {
			httpError(w, codeAddressRequired, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// atAAL2 is whether the caller's session passed a second factor.
func atAAL2(claims *auth.Claims) bool {
	return claims != nil && claims.AAL == claimAAL2
}

// enrolledNeedsAAL2 refuses an aal1 session of an account that has a verified
// factor while MFA is on, so a stolen password alone cannot change how the
// account signs in. It answers and returns false on refusal.
func (h *AuthHandler) enrolledNeedsAAL2(w http.ResponseWriter, r *http.Request, info pool.ProjectInfo, db store.Store, claims *auth.Claims) bool {
	if !info.MFAEnabled || atAAL2(claims) {
		return true
	}
	enrolled, err := db.HasVerifiedFactor(r.Context(), claims.UserID)
	if err != nil {
		writeStoreFailure(w, err, errUserNotFound.Error())
		return false
	}
	if enrolled {
		httpError(w, codeInsufficientAAL, http.StatusForbidden)
		return false
	}
	return true
}

// mfaKeys reads the project's key from the vault; 503 when it cannot be.
func (h *AuthHandler) mfaKeys(w http.ResponseWriter, r *http.Request) (mfa.Keys, bool) {
	projectID := projectKey(r)
	key, err := h.poolMgr.MFAKey(r.Context(), projectID)
	if err == nil {
		keys, keyErr := mfa.NewKeys(key)
		if keyErr == nil {
			return keys, true
		}
		err = keyErr
	}
	log.Printf("auth.mfa.key_unavailable project=%s: %v", safeLog(projectID), err)
	httpError(w, codeMFAUnavailable, http.StatusServiceUnavailable)
	return mfa.Keys{}, false
}

type factorJSON struct {
	ID           string    `json:"id"`
	FactorType   string    `json:"factorType"`
	FriendlyName string    `json:"friendlyName"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

func factorView(factor store.Factor) factorJSON {
	return factorJSON{ID: factor.ID, FactorType: factor.FactorType, FriendlyName: factor.FriendlyName,
		Status: factor.Status, CreatedAt: factor.CreatedAt, UpdatedAt: factor.UpdatedAt}
}

// ListFactors answers the caller's factors and unspent recovery codes.
func (h *AuthHandler) ListFactors(w http.ResponseWriter, r *http.Request) {
	db, ok := h.storeFor(w, r)
	if !ok {
		return
	}
	listing, err := db.ListFactors(r.Context(), middleware.ClaimsFromContext(r.Context()).UserID)
	if err != nil {
		writeStoreFailure(w, err, errUserNotFound.Error())
		return
	}
	factors := make([]factorJSON, 0, len(listing.Factors))
	for _, factor := range listing.Factors {
		factors = append(factors, factorView(factor))
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{"factors": factors, "recoveryCodesRemaining": listing.RecoveryCodesRemaining})
}

type enrollRequest struct {
	FactorType   string `json:"factorType"`
	FriendlyName string `json:"friendlyName"`
	Issuer       string `json:"issuer"`
}

// printable is short, valid UTF-8 text with no control characters.
func printable(text string, limit int) bool {
	return utf8.ValidString(text) && utf8.RuneCountInString(text) <= limit && !strings.ContainsFunc(text, unicode.IsControl)
}

func decodeEnrollRequest(w http.ResponseWriter, r *http.Request) (enrollRequest, bool) {
	var req enrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxFactorBody)).Decode(&req); err != nil {
		httpError(w, codeInvalidRequest, http.StatusBadRequest)
		return req, false
	}
	req.FriendlyName, req.Issuer = strings.TrimSpace(req.FriendlyName), strings.TrimSpace(req.Issuer)
	// The issuer heads the app's label, where a colon would split it.
	if req.FactorType != store.FactorTOTP || !printable(req.FriendlyName, maxFriendlyName) ||
		!printable(req.Issuer, maxIssuer) || strings.Contains(req.Issuer, ":") {
		httpError(w, codeInvalidRequest, http.StatusBadRequest)
		return req, false
	}
	return req, true
}

// EnrollFactor adds an unverified TOTP factor and hands its secret back once.
func (h *AuthHandler) EnrollFactor(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeEnrollRequest(w, r)
	if !ok {
		return
	}
	info, ok := h.mfaSettings(w, r)
	if !ok {
		return
	}
	db, ok := h.storeFor(w, r)
	claims := middleware.ClaimsFromContext(r.Context())
	if !ok || !h.enrolledNeedsAAL2(w, r, info, db, claims) {
		return
	}
	keys, ok := h.mfaKeys(w, r)
	if !ok {
		return
	}
	secret, err := mfa.NewSecret()
	if err != nil {
		httpError(w, "internal error", http.StatusInternalServerError)
		return
	}
	factorID := uuid.NewString()
	sealed, err := keys.Seal(secret, claims.UserID, factorID)
	if err != nil {
		httpError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if req.FriendlyName == "" {
		req.FriendlyName = defaultFactorTag + " " + factorID[:8]
	}
	factor, err := db.CreateFactor(r.Context(), store.NewFactor{ID: factorID, UserID: claims.UserID,
		FriendlyName: req.FriendlyName, SecretSealed: sealed}, h.mfaLimits)
	if !writeEnrollFailure(w, err) {
		return
	}
	h.recordAudit(r.Context(), db, projectKey(r), store.AuditEvent{UserID: claims.UserID, Event: "mfa_enrolled", Method: methodTOTP, IP: h.clientIP(r)})
	issuer := req.Issuer
	if issuer == "" {
		issuer = h.labelsFor(r, projectKey(r)).projectName
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"id": factor.ID, "factorType": factor.FactorType, "friendlyName": factor.FriendlyName,
		"status": factor.Status, "totp": map[string]string{"secret": mfa.EncodeSecret(secret),
			"uri": mfa.KeyURI(strings.ReplaceAll(issuer, ":", " "), accountLabel(claims), secret)}})
}

// accountLabel names the account in the authenticator app.
func accountLabel(claims *auth.Claims) string {
	if claims.Email != "" {
		return claims.Email
	}
	return fmt.Sprintf("user-%d", claims.UserID)
}

// writeEnrollFailure answers a refused enrolment; true when there was none.
func writeEnrollFailure(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, store.ErrTooManyFactors):
		httpError(w, codeTooManyFactors, http.StatusConflict)
	case errors.Is(err, store.ErrFactorNameTaken):
		httpError(w, codeFactorNameTaken, http.StatusConflict)
	default:
		writeStoreFailure(w, err, errUserNotFound.Error())
	}
	return false
}

// ChallengeFactor opens a five-minute challenge for one of the caller's factors.
func (h *AuthHandler) ChallengeFactor(w http.ResponseWriter, r *http.Request) {
	db, ok := h.storeFor(w, r)
	if !ok {
		return
	}
	challengeID := uuid.NewString()
	expiresAt := time.Now().Add(mfaChallengeTTL).UTC().Truncate(time.Second)
	err := db.CreateChallenge(r.Context(), middleware.ClaimsFromContext(r.Context()).UserID,
		chi.URLParam(r, "factorId"), challengeID, otpSenderKey(h.clientIP(r)), expiresAt)
	if err != nil {
		writeStoreFailure(w, err, codeFactorNotFound)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"id": challengeID, "expiresAt": expiresAt})
}

// UnenrollFactor removes one of the caller's factors; once the account has a
// verified factor that takes an aal2 session.
func (h *AuthHandler) UnenrollFactor(w http.ResponseWriter, r *http.Request) {
	info, ok := h.mfaSettings(w, r)
	if !ok {
		return
	}
	db, ok := h.storeFor(w, r)
	claims := middleware.ClaimsFromContext(r.Context())
	if !ok || !h.enrolledNeedsAAL2(w, r, info, db, claims) {
		return
	}
	if err := db.DeleteFactor(r.Context(), claims.UserID, chi.URLParam(r, "factorId")); err != nil {
		writeStoreFailure(w, err, codeFactorNotFound)
		return
	}
	h.recordAudit(r.Context(), db, projectKey(r), store.AuditEvent{UserID: claims.UserID, Event: "mfa_unenrolled", Method: methodTOTP, IP: h.clientIP(r)})
	w.WriteHeader(http.StatusNoContent)
}
