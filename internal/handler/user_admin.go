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
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultUsersLimit = 100
	maxUsersLimit     = 500
	maxActorLength    = 256
	maxSetRoleBody    = 16 << 10
)

var errUserNotFound = errors.New("user_not_found")

type actorCtxKey struct{}

// UserRoutes registers the end-user role endpoints. Routes mounts them behind
// RequireJWT and requireUserManager.
func (h *AuthHandler) UserRoutes(r chi.Router) {
	r.Get("/", h.ListUsers)
	r.With(h.limit(rateLimitToken)).Put("/{userId}/role", h.SetUserRole)
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
	pool, err := h.poolMgr.GetPool(r.Context(), chi.URLParam(r, "orgSlug"), projectKey(r))
	if err != nil {
		writePoolFailure(w, err)
		return
	}
	users, err := listUsers(r.Context(), pool, limit, offset)
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

func listUsers(ctx context.Context, pool *pgxpool.Pool, limit, offset int) ([]domain.ManagedUser, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, email, role, allowed_roles, enabled, email_verified
		 FROM auth.users ORDER BY id LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]domain.ManagedUser, 0)
	for rows.Next() {
		user, err := scanManagedUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func scanManagedUser(row pgx.Row) (domain.ManagedUser, error) {
	var user domain.ManagedUser
	err := row.Scan(&user.ID, &user.Email, &user.Role, &user.AllowedRoles, &user.Enabled, &user.EmailVerified)
	if user.AllowedRoles == nil {
		user.AllowedRoles = []string{user.Role}
	}
	return user, err
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
	pool, err := h.poolMgr.GetPool(r.Context(), chi.URLParam(r, "orgSlug"), projectKey(r))
	if err != nil {
		writePoolFailure(w, err)
		return
	}
	change := roleChange{userID: userID, role: req.Role, allowed: allowed, actor: actorFrom(r.Context())}
	if req.AllowedRoles != nil {
		change.stored = allowed
	}
	user, err := applyRoleChange(r.Context(), pool, change)
	if errors.Is(err, errUserNotFound) {
		httpError(w, errUserNotFound.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		httpError(w, "failed_to_change_role", http.StatusInternalServerError)
		return
	}
	log.Printf("auth.users.role_changed project=%s user=%d role=%s actor=%s",
		safeLog(projectKey(r)), userID, req.Role, safeLog(change.actor))
	writeJSON(w, user)
}

func actorFrom(ctx context.Context) string {
	actor, _ := ctx.Value(actorCtxKey{}).(string)
	return actor
}

// roleChange is one validated change; stored is what users.allowed_roles
// receives (nil when the caller gave no list) and allowed its reading.
type roleChange struct {
	userID  int64
	role    string
	allowed []string
	stored  []string
	actor   string
}

// applyRoleChange updates the account, revokes every refresh token it holds
// and writes the audit row in one transaction.
func applyRoleChange(ctx context.Context, pool *pgxpool.Pool, change roleChange) (domain.ManagedUser, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return domain.ManagedUser{}, err
	}
	defer tx.Rollback(ctx)

	before, err := scanManagedUser(tx.QueryRow(ctx,
		`SELECT id, email, role, allowed_roles, enabled, email_verified
		 FROM auth.users WHERE id = $1 FOR UPDATE`, change.userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ManagedUser{}, errUserNotFound
	}
	if err != nil {
		return domain.ManagedUser{}, err
	}
	statements := []struct {
		sql  string
		args []any
	}{
		{`UPDATE auth.users SET role = $2, allowed_roles = $3, updated_at = NOW() WHERE id = $1`,
			[]any{change.userID, change.role, change.stored}},
		{`UPDATE auth.refresh_tokens SET revoked = true WHERE user_id = $1 AND revoked = false`,
			[]any{change.userID}},
		{`INSERT INTO auth.role_changes (user_id, old_role, new_role, old_allowed_roles, new_allowed_roles, actor)
		  VALUES ($1, $2, $3, $4, $5, $6)`,
			[]any{change.userID, before.Role, change.role, before.AllowedRoles, change.allowed, change.actor}},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
			return domain.ManagedUser{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.ManagedUser{}, err
	}
	after := before
	after.Role, after.AllowedRoles = change.role, change.allowed
	return after, nil
}
