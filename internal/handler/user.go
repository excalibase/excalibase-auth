package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/middleware"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/store"
)

const (
	// maxUserBody fits a metadata object at its limit with room for escaping.
	maxUserBody = 40 << 10

	codeInvalidRequest   = "invalid_request"
	codeInvalidMetadata  = "invalid_metadata"
	codeMetadataTooLarge = "metadata_too_large"
	codeInvalidFullName  = "invalid_full_name"
	codeSameEmail        = "email_unchanged"
	// A password change ends every pending address change, so the two are
	// never asked for at once.
	codeOneSensitiveChange = "password_and_email_separately"
	// codeAddressRequired refuses a password on a guest: it could never sign in with one.
	codeAddressRequired = "email_required"
)

// updateUserRequest is PATCH /user. App metadata is not a field: only the
// project writes it, so a body naming it is refused as unknown.
type updateUserRequest struct {
	FullName        *string         `json:"fullName"`
	Data            json.RawMessage `json:"data"`
	Email           *string         `json:"email"`
	EmailRedirectTo string          `json:"emailRedirectTo"`
	Password        *string         `json:"password"`
	CurrentPassword *string         `json:"currentPassword"`
}

// userUpdate is a validated request.
type userUpdate struct {
	request updateUserRequest
	profile store.ProfileChange
	email   string
}

func (u userUpdate) sensitive() bool { return u.request.Password != nil || u.email != "" }

// userAPISettings reads the settings fresh: 503 when unreadable, 404 while
// account self-service is off for the project.
func (h *AuthHandler) userAPISettings(w http.ResponseWriter, r *http.Request) (pool.ProjectInfo, bool) {
	info, err := h.signInSettings(r.Context(), projectKey(r))
	if err != nil {
		httpError(w, errSettingsUnreadable, http.StatusServiceUnavailable)
		return info, false
	}
	if !info.UserAPIEnabled {
		httpError(w, codeMethodOff, http.StatusNotFound)
		return info, false
	}
	return info, true
}

// requireUserAPI answers before anything else is read while the routes are off.
func (h *AuthHandler) requireUserAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := h.userAPISettings(w, r); ok {
			next.ServeHTTP(w, r)
		}
	})
}

func accountUser(profile store.Profile) domain.AccountUser {
	return domain.AccountUser{ID: profile.ID, Email: profile.Email, FullName: profile.FullName,
		EmailVerified: profile.EmailVerified, IsGuest: profile.IsGuest, HasPassword: store.HasUsablePassword(profile.PasswordHash),
		UserMetadata: profile.UserMetadata, AppMetadata: profile.AppMetadata, CreatedAt: profile.CreatedAt}
}

// GetUser answers the caller's own account with its metadata.
func (h *AuthHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	db, ok := h.storeFor(w, r)
	if !ok {
		return
	}
	profile, err := db.Profile(r.Context(), middleware.ClaimsFromContext(r.Context()).UserID)
	if err != nil {
		writeStoreFailure(w, err, errUserNotFound.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, accountUser(profile))
}

// UpdateUser changes the caller's name and metadata, and with a recent sign-in
// (or, for the password, the current one) the password and the address.
func (h *AuthHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	info, ok := h.userAPISettings(w, r)
	if !ok {
		return
	}
	update, ok := decodeUserUpdate(w, r)
	if !ok {
		return
	}
	redirectTo := ""
	if update.email != "" {
		if redirectTo, ok = emailChangeTarget(w, update.request.EmailRedirectTo, info); !ok {
			return
		}
	}
	db, ok := h.storeFor(w, r)
	if !ok {
		return
	}
	claims := middleware.ClaimsFromContext(r.Context())
	account, ok := h.userAccount(w, r, db, claims.UserID)
	if !ok || !h.mayChangeSensitive(w, r, db, update, claims, account) {
		return
	}
	result, ok := h.applyUserUpdate(w, r, db, update, account, redirectTo)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, result)
}

func (h *AuthHandler) userAccount(w http.ResponseWriter, r *http.Request, db store.Store, userID int64) (store.Account, bool) {
	account, err := db.AccountByID(r.Context(), userID)
	switch {
	case err != nil:
		writeStoreFailure(w, err, errUserNotFound.Error())
		return account, false
	case !account.Enabled:
		httpError(w, errAccountDisabled.Error(), http.StatusForbidden)
		return account, false
	}
	return account, true
}

func decodeUserUpdate(w http.ResponseWriter, r *http.Request) (userUpdate, bool) {
	var update userUpdate
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxUserBody))
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&update.request) != nil {
		httpError(w, codeInvalidRequest, http.StatusBadRequest)
		return update, false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		httpError(w, codeInvalidRequest, http.StatusBadRequest)
		return update, false
	}
	if code, err := update.validate(); err != nil {
		httpError(w, code, http.StatusBadRequest)
		return update, false
	}
	return update, true
}

// validate checks every field before anything is changed; it answers the
// error code to send.
func (u *userUpdate) validate() (string, error) {
	req := u.request
	if req.FullName != nil {
		name := strings.TrimSpace(*req.FullName)
		if !validFullName(name) {
			return codeInvalidFullName, errors.New(codeInvalidFullName)
		}
		u.profile.FullName = &name
	}
	if req.Data != nil {
		patch, err := store.ParseMetadataPatch(req.Data)
		if err != nil {
			return codeInvalidMetadata, err
		}
		u.profile.UserMetadata = patch
	}
	if req.Password != nil {
		if err := validatePassword(*req.Password); err != nil {
			return err.Error(), err
		}
	}
	if req.Email != nil && req.Password != nil {
		return codeOneSensitiveChange, errors.New(codeOneSensitiveChange)
	}
	if req.Email != nil {
		u.email = strings.TrimSpace(*req.Email)
		if !validAddress(u.email) || !asciiOnly(u.email) {
			return errInvalidEmail.Error(), errInvalidEmail
		}
	}
	return "", nil
}

func validFullName(name string) bool {
	return name != "" && utf8.RuneCountInString(name) <= maxFullName && !strings.ContainsFunc(name, unicode.IsControl)
}

// mayChangeSensitive answers for a password or address change the caller may
// not make: one needs a recent sign-in, a password change may instead show
// the current password, and an address change needs the own one proven.
func (h *AuthHandler) mayChangeSensitive(w http.ResponseWriter, r *http.Request, db store.Store, update userUpdate, claims *auth.Claims, account store.Account) bool {
	if !update.sensitive() {
		return true
	}
	if update.request.Password != nil && account.IsGuest {
		httpError(w, codeAddressRequired, http.StatusBadRequest)
		return false
	}
	if update.email != "" && store.AddressKey(update.email) == store.AddressKey(account.Email) {
		httpError(w, codeSameEmail, http.StatusBadRequest)
		return false
	}
	recent := freshEnough(claims, account.IsGuest, time.Now())
	if update.email != "" && !recent {
		httpError(w, codeReauthRequired, http.StatusForbidden)
		return false
	}
	if update.request.Password != nil && !recent && !h.currentPasswordMatches(w, r, update, account) {
		return false
	}
	return update.email == "" || linkable(w, r, db, account.ID)
}

// currentPasswordMatches checks the current password under the address's
// sign-in lock, so the route cannot be used to guess it.
func (h *AuthHandler) currentPasswordMatches(w http.ResponseWriter, r *http.Request, update userUpdate, account store.Account) bool {
	current := update.request.CurrentPassword
	if current == nil || !store.HasUsablePassword(account.PasswordHash) {
		httpError(w, codeReauthRequired, http.StatusForbidden)
		return false
	}
	if h.limits != nil && h.limits.PasswordLockedOut(account.Email) {
		httpError(w, codeRateLimited, http.StatusTooManyRequests)
		return false
	}
	matched, err := h.checkPassword(r.Context(), *current, account.PasswordHash)
	if err != nil {
		writeHashFailure(w, err)
		return false
	}
	if h.limits != nil {
		h.limits.RecordPasswordCheck(account.Email, matched)
	}
	if !matched {
		httpError(w, codeReauthRequired, http.StatusForbidden)
	}
	return matched
}

type updateUserResponse struct {
	User                 domain.AccountUser   `json:"user"`
	EmailChangeRequested bool                 `json:"emailChangeRequested,omitempty"`
	Session              *domain.AuthResponse `json:"session,omitempty"`
}

// applyUserUpdate makes the changes in order: name and metadata, password,
// then the address change request.
func (h *AuthHandler) applyUserUpdate(w http.ResponseWriter, r *http.Request, db store.Store, update userUpdate, account store.Account, redirectTo string) (updateUserResponse, bool) {
	var result updateUserResponse
	profile, err := db.UpdateProfile(r.Context(), account.ID, update.profile)
	if errors.Is(err, store.ErrMetadataTooLarge) {
		httpError(w, codeMetadataTooLarge, http.StatusBadRequest)
		return result, false
	}
	if err != nil {
		writeStoreFailure(w, err, errUserNotFound.Error())
		return result, false
	}
	if update.request.Password != nil {
		if result.Session, err = h.changePassword(r, db, account, *update.request.Password); err != nil {
			writeError(w, err, statusOf(err))
			return result, false
		}
	}
	if update.email != "" {
		if !h.requestEmailChange(w, r, db, account, update.email, redirectTo) {
			return result, false
		}
		result.EmailChangeRequested = true
	}
	result.User = accountUser(profile)
	result.User.HasPassword = result.User.HasPassword || update.request.Password != nil
	return result, true
}

// statusError carries the status a failure is answered with.
type statusError struct {
	status int
	err    error
}

func (e statusError) Error() string { return e.err.Error() }
func (e statusError) Unwrap() error { return e.err }

func statusOf(err error) int {
	var withStatus statusError
	if errors.As(err, &withStatus) {
		return withStatus.status
	}
	return http.StatusInternalServerError
}

// changePassword stores the new password, ends every session of the account
// and starts this one again, keeping when its owner signed in.
func (h *AuthHandler) changePassword(r *http.Request, db store.Store, account store.Account, password string) (*domain.AuthResponse, error) {
	hash, err := h.hasher.Hash(r.Context(), password)
	if err != nil {
		if errors.Is(err, auth.ErrHashBusy) {
			return nil, statusError{http.StatusServiceUnavailable, errHashingBusy}
		}
		return nil, statusError{http.StatusInternalServerError, errors.New("internal error")}
	}
	if err := db.ChangePassword(r.Context(), account.ID, hash); err != nil {
		return nil, statusError{http.StatusInternalServerError, errors.New("failed to change password")}
	}
	projectID := projectKey(r)
	h.recordAudit(r.Context(), db, projectID, store.AuditEvent{UserID: account.ID, Event: "password_changed", IP: h.clientIP(r)})
	log.Printf("auth.user.password_changed project=%s userId=%d", safeLog(projectID), account.ID)
	session := h.newRefreshSession()
	session.AuthTime = time.Time{}
	if signedIn := middleware.ClaimsFromContext(r.Context()).AuthTime; signedIn != 0 {
		session.AuthTime = time.Unix(signedIn, 0)
	}
	user := userInfoOf(account)
	resp, err := h.startSession(r, projectID, user, accountRoles{role: account.Role, allowed: account.AllowedRoles}, account.EmailVerified, session)
	if err != nil {
		status, failure := sessionFailure(err)
		return nil, statusError{status, failure}
	}
	return resp, nil
}
