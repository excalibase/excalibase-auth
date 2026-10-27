package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/store"
	"github.com/go-chi/chi/v5"
)

const codeUserReferenced = "user_referenced"

// managedUserChange is PATCH /users/{id}: only the project writes app metadata.
type managedUserChange struct {
	AppMetadata  json.RawMessage `json:"appMetadata"`
	UserMetadata json.RawMessage `json:"userMetadata"`
	FullName     *string         `json:"fullName"`
}

func managedUserDetail(profile store.Profile) domain.ManagedUserDetail {
	allowed := profile.AllowedRoles
	if allowed == nil {
		allowed = []string{profile.Role}
	}
	return domain.ManagedUserDetail{
		ManagedUser: domain.ManagedUser{ID: profile.ID, Email: profile.Email, Role: profile.Role, AllowedRoles: allowed,
			Enabled: profile.Enabled, EmailVerified: profile.EmailVerified},
		FullName: profile.FullName, UserMetadata: profile.UserMetadata, AppMetadata: profile.AppMetadata,
		CreatedAt: profile.CreatedAt, LastLoginAt: profile.LastLoginAt,
	}
}

// managedTarget reads the account id and the settings, answering for either.
func (h *AuthHandler) managedTarget(w http.ResponseWriter, r *http.Request) (int64, store.Store, bool) {
	if _, ok := h.userAPISettings(w, r); !ok {
		return 0, nil, false
	}
	userID, err := strconv.ParseInt(chi.URLParam(r, "userId"), 10, 64)
	if err != nil || userID <= 0 {
		httpError(w, "invalid_user_id", http.StatusBadRequest)
		return 0, nil, false
	}
	db, ok := h.storeFor(w, r)
	return userID, db, ok
}

// GetManagedUser answers one account with its metadata.
func (h *AuthHandler) GetManagedUser(w http.ResponseWriter, r *http.Request) {
	userID, db, ok := h.managedTarget(w, r)
	if !ok {
		return
	}
	profile, err := db.Profile(r.Context(), userID)
	if err != nil {
		writeStoreFailure(w, err, errUserNotFound.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, managedUserDetail(profile))
}

// UpdateManagedUser merges app and user metadata and sets the name.
func (h *AuthHandler) UpdateManagedUser(w http.ResponseWriter, r *http.Request) {
	userID, db, ok := h.managedTarget(w, r)
	if !ok {
		return
	}
	change, code := decodeManagedChange(w, r)
	if code != "" {
		httpError(w, code, http.StatusBadRequest)
		return
	}
	profile, err := db.UpdateProfile(r.Context(), userID, change)
	if errors.Is(err, store.ErrMetadataTooLarge) {
		httpError(w, codeMetadataTooLarge, http.StatusBadRequest)
		return
	}
	if err != nil {
		writeStoreFailure(w, err, errUserNotFound.Error())
		return
	}
	log.Printf("auth.users.updated project=%s user=%d actor=%s", safeLog(projectKey(r)), userID, safeLog(actorFrom(r.Context())))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, managedUserDetail(profile))
}

// decodeManagedChange answers the error code of a body it refuses.
func decodeManagedChange(w http.ResponseWriter, r *http.Request) (store.ProfileChange, string) {
	var (
		body   managedUserChange
		change store.ProfileChange
	)
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2*maxUserBody))
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&body) != nil {
		return change, codeInvalidRequest
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return change, codeInvalidRequest
	}
	if body.FullName != nil {
		name := strings.TrimSpace(*body.FullName)
		if !validFullName(name) {
			return change, codeInvalidFullName
		}
		change.FullName = &name
	}
	for _, part := range []struct {
		raw    json.RawMessage
		target *map[string]json.RawMessage
	}{{body.AppMetadata, &change.AppMetadata}, {body.UserMetadata, &change.UserMetadata}} {
		if part.raw == nil {
			continue
		}
		patch, err := store.ParseMetadataPatch(part.raw)
		if err != nil {
			return change, codeInvalidMetadata
		}
		*part.target = patch
	}
	return change, ""
}

// DeleteManagedUser removes an account and its sessions, links and keys.
func (h *AuthHandler) DeleteManagedUser(w http.ResponseWriter, r *http.Request) {
	userID, db, ok := h.managedTarget(w, r)
	if !ok {
		return
	}
	err := db.DeleteUser(r.Context(), userID)
	switch {
	case errors.Is(err, store.ErrUserReferenced):
		httpError(w, codeUserReferenced, http.StatusConflict)
		return
	case err != nil:
		writeStoreFailure(w, err, errUserNotFound.Error())
		return
	}
	actor := actorFrom(r.Context())
	h.recordAudit(r.Context(), db, projectKey(r), store.AuditEvent{UserID: userID, Event: "user_deleted", Method: auditActorKind(actor), IP: h.clientIP(r)})
	log.Printf("auth.users.deleted project=%s user=%d actor=%s", safeLog(projectKey(r)), userID, safeLog(actor))
	w.WriteHeader(http.StatusNoContent)
}

// auditActorKind keeps the audit row's method to who deleted: studio or a service key.
func auditActorKind(actor string) string {
	kind, _, _ := strings.Cut(actor, ":")
	return kind
}
