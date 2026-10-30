package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"unicode"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/middleware"
	"github.com/excalibase/auth/internal/store"
	"github.com/go-chi/chi/v5"
)

const (
	defaultUsersLimit = 100
	maxUsersLimit     = 500
	maxActorLength    = 256
	maxSetRoleBody    = 16 << 10
)

var errUserNotFound = errors.New("user_not_found")

type actorCtxKey struct{}

// UserRoutes registers the end-user administration endpoints. Routes mounts them behind
// RequireJWT and requireUserManager.
func (h *AuthHandler) UserRoutes(r chi.Router) {
	r.Get("/", h.ListUsers)
	r.With(h.limit(rateLimitToken)).Put("/{userId}/role", h.SetUserRole)
	r.Get("/{userId}", h.GetManagedUser)
	r.With(h.limit(rateLimitToken)).Patch("/{userId}", h.UpdateManagedUser)
	r.With(h.limit(rateLimitToken)).Delete("/{userId}", h.DeleteManagedUser)
	r.With(h.limit(rateLimitToken)).Delete("/{userId}/factors", h.ResetUserMFA)
}

// requireUserManager admits only callers allowed to manage the project's
// end-user roles and records who they are for the audit trail.
func requireUserManager(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFromContext(r.Context())
		if claims == nil {
			httpError(w, "missing_token", http.StatusUnauthorized)
			return
		}
		projectID := projectKey(r)
		if claims.ProjectID != projectID {
			httpError(w, "token_project_mismatch", http.StatusForbidden)
			return
		}
		actor, ok := userManagerActor(claims, projectID)
		if !ok {
			httpError(w, "insufficient_scope", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorCtxKey{}, actor)))
	})
}

// userManagerActor accepts the control plane's user-admin token, which names
// the platform user, or the project's secret-key token. End-user, anon and
// key-admin tokens are refused.
func userManagerActor(claims *auth.Claims, projectID string) (string, bool) {
	if claims.TokenUse == auth.TokenUseUserAdmin {
		if !isPlatformTokenFor(claims, projectID) || !validActor(claims.Actor) {
			return "", false
		}
		return "studio:" + claims.Actor, true
	}
	if claims.IsAccess() && claims.Role == auth.RoleService && claims.Scope == "service" && claims.KeyID > 0 {
		return fmt.Sprintf("service-key:%d", claims.KeyID), true
	}
	return "", false
}

func validActor(actor string) bool {
	if strings.TrimSpace(actor) == "" || len(actor) > maxActorLength {
		return false
	}
	return !strings.ContainsFunc(actor, unicode.IsControl)
}

// ListUsers answers the project's accounts ordered by id.
func (h *AuthHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := parsePagination(r)
	if err != nil {
		httpError(w, "invalid_pagination", http.StatusBadRequest)
		return
	}
	db, err := h.poolMgr.GetStore(r.Context(), chi.URLParam(r, "orgSlug"), projectKey(r))
	if err != nil {
		writePoolFailure(w, err)
		return
	}
	users, err := db.ListUsers(r.Context(), limit, offset)
	if err != nil {
		httpError(w, "failed_to_list_users", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"users": users})
}

func parsePagination(r *http.Request) (int, int, error) {
	limit, err := queryInt(r, "limit", defaultUsersLimit)
	if err != nil || limit < 1 || limit > maxUsersLimit {
		return 0, 0, errors.New("invalid limit")
	}
	offset, err := queryInt(r, "offset", 0)
	if err != nil || offset < 0 {
		return 0, 0, errors.New("invalid offset")
	}
	return limit, offset, nil
}

func queryInt(r *http.Request, name string, fallback int) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback, nil
	}
	return strconv.Atoi(raw)
}

// SetUserRole replaces an account's role and allowed roles. Every session of
// the account ends, so the new roles apply from its next sign-in.
func (h *AuthHandler) SetUserRole(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(chi.URLParam(r, "userId"), 10, 64)
	if err != nil || userID <= 0 {
		httpError(w, "invalid_user_id", http.StatusBadRequest)
		return
	}
	var req domain.SetRoleRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSetRoleBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		httpError(w, "invalid_request", http.StatusBadRequest)
		return
	}
	allowed, err := auth.NormalizeAllowedRoles(req.Role, req.AllowedRoles)
	if err != nil {
		httpError(w, err.Error(), http.StatusBadRequest)
		return
	}
	db, err := h.poolMgr.GetStore(r.Context(), chi.URLParam(r, "orgSlug"), projectKey(r))
	if err != nil {
		writePoolFailure(w, err)
		return
	}
	change := store.RoleChange{UserID: userID, Role: req.Role, Allowed: allowed, Actor: actorFrom(r.Context())}
	if req.AllowedRoles != nil {
		change.Stored = allowed
	}
	user, err := db.ApplyRoleChange(r.Context(), change)
	if errors.Is(err, store.ErrNotFound) {
		httpError(w, errUserNotFound.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		httpError(w, "failed_to_change_role", http.StatusInternalServerError)
		return
	}
	log.Printf("auth.users.role_changed project=%s user=%d role=%s actor=%s",
		safeLog(projectKey(r)), userID, req.Role, safeLog(change.Actor))
	writeJSON(w, user)
}

func actorFrom(ctx context.Context) string {
	actor, _ := ctx.Value(actorCtxKey{}).(string)
	return actor
}
