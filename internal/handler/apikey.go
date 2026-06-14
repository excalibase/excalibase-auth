package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/middleware"
	"github.com/excalibase/auth/internal/service"
	"github.com/go-chi/chi/v5"
)

// APIKeyRoutes registers the api-key CRUD endpoints. The caller is responsible
// for wrapping the returned subrouter with middleware.RequireJWT — keeping the
// auth requirement explicit at the route registration site instead of buried
// inside this file makes it impossible to accidentally publish the endpoints
// unauthenticated.
func (h *AuthHandler) APIKeyRoutes(r chi.Router) {
	r.Post("/", h.CreateAPIKey)
	r.Get("/", h.ListAPIKeys)
	r.Delete("/{id}", h.RevokeAPIKey)
}

// canManageAPIKeys reports whether the token scope is permitted to manage api
// keys. Publishable / browser ("public") tokens are read-only credentials for
// edge traffic and must never create, list, or revoke keys. Only first-party
// authenticated users and trusted service tokens may.
func canManageAPIKeys(scope string) bool {
	return scope == "authenticated" || scope == "service"
}

// CreateAPIKey generates a new api key for the project, stores its hash, and
// returns the plaintext exactly once.
func (h *AuthHandler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	projectID := projectKey(r)
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		httpError(w, "missing claims", 401)
		return
	}
	if claims.ProjectID != projectID {
		httpError(w, "token project mismatch", http.StatusForbidden)
		return
	}
	if !canManageAPIKeys(claims.Scope) {
		httpError(w, "insufficient scope to manage api keys", http.StatusForbidden)
		return
	}

	var req domain.CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "invalid request", 400)
		return
	}
	if req.KeyType != string(service.KeyTypePublishable) && req.KeyType != string(service.KeyTypeSecret) {
		httpError(w, "keyType must be 'publishable' or 'secret'", 400)
		return
	}

	pool, err := h.poolMgr.GetPool(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		httpError(w, errProjectDBUnavailable.Error(), 503)
		return
	}

	plaintext, hash, prefix, err := service.GenerateAPIKey(service.KeyType(req.KeyType))
	if err != nil {
		httpError(w, "failed to generate api key", 500)
		return
	}

	var (
		id        int64
		createdAt time.Time
	)
	err = pool.QueryRow(r.Context(),
		`INSERT INTO auth.api_keys (key_hash, key_prefix, key_type, name, created_by)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, created_at`,
		hash, prefix, req.KeyType, req.Name, claims.UserID,
	).Scan(&id, &createdAt)
	if err != nil {
		httpError(w, "failed to persist api key", 500)
		return
	}

	w.WriteHeader(201)
	writeJSON(w, domain.CreateAPIKeyResponse{
		ID:        id,
		Plaintext: plaintext,
		KeyPrefix: prefix,
		KeyType:   req.KeyType,
		Name:      req.Name,
		CreatedAt: createdAt.Format(time.RFC3339),
	})
}

// ListAPIKeys returns the non-revoked keys for the project. Hashes and
// plaintext are never included in the response.
func (h *AuthHandler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	projectID := projectKey(r)
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		httpError(w, "missing claims", 401)
		return
	}
	if claims.ProjectID != projectID {
		httpError(w, "token project mismatch", http.StatusForbidden)
		return
	}
	if !canManageAPIKeys(claims.Scope) {
		httpError(w, "insufficient scope to manage api keys", http.StatusForbidden)
		return
	}

	pool, err := h.poolMgr.GetPool(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		httpError(w, errProjectDBUnavailable.Error(), 503)
		return
	}

	rows, err := pool.Query(r.Context(),
		`SELECT id, key_prefix, key_type, COALESCE(name, ''), created_at, last_used_at
		 FROM auth.api_keys
		 WHERE revoked_at IS NULL
		 ORDER BY created_at DESC`,
	)
	if err != nil {
		httpError(w, "failed to query api keys", 500)
		return
	}
	defer rows.Close()

	keys := make([]domain.APIKeyInfo, 0)
	for rows.Next() {
		var info domain.APIKeyInfo
		var createdAt time.Time
		var lastUsed *time.Time
		if err := rows.Scan(&info.ID, &info.KeyPrefix, &info.KeyType, &info.Name, &createdAt, &lastUsed); err != nil {
			httpError(w, "failed to scan api key", 500)
			return
		}
		info.CreatedAt = createdAt.Format(time.RFC3339)
		if lastUsed != nil {
			s := lastUsed.Format(time.RFC3339)
			info.LastUsedAt = &s
		}
		keys = append(keys, info)
	}

	writeJSON(w, map[string]interface{}{"keys": keys})
}

// RevokeAPIKey soft-deletes a key by setting revoked_at and revoked_by.
// Idempotent: revoking an already-revoked key returns 204 without error.
func (h *AuthHandler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	projectID := projectKey(r)
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		httpError(w, "missing claims", 401)
		return
	}
	if claims.ProjectID != projectID {
		httpError(w, "token project mismatch", http.StatusForbidden)
		return
	}
	if !canManageAPIKeys(claims.Scope) {
		httpError(w, "insufficient scope to manage api keys", http.StatusForbidden)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httpError(w, "invalid api key id", 400)
		return
	}

	pool, err := h.poolMgr.GetPool(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		httpError(w, errProjectDBUnavailable.Error(), 503)
		return
	}

	tag, err := pool.Exec(r.Context(),
		`UPDATE auth.api_keys
		 SET revoked_at = NOW(), revoked_by = $1
		 WHERE id = $2 AND revoked_at IS NULL`,
		claims.UserID, id,
	)
	if err != nil {
		httpError(w, "failed to revoke api key", 500)
		return
	}
	if tag.RowsAffected() == 0 {
		// Either id doesn't exist or already revoked. We treat both as success
		// (idempotent) but return a hint in the body.
		writeJSON(w, map[string]string{"status": "already_revoked_or_missing"})
		return
	}
	w.WriteHeader(204)
}
