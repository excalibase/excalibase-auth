package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/middleware"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// Shared sentinel errors so HTTP handlers and the unified /token dispatch
// surface identical messages.
var (
	errProjectDBUnavailable = errors.New("failed to connect to project database")
	errInvalidCredentials   = errors.New("invalid email or password")
	errAccountDisabled      = errors.New("account is disabled")
	errInvalidRefreshToken  = errors.New("invalid refresh token")
	errRefreshTokenRevoked  = errors.New("refresh token revoked")
	errRefreshTokenExpired  = errors.New("refresh token expired")
	errTokenGeneration      = errors.New("failed to generate tokens")
	errMissingAPIKey        = errors.New("api_key is required")
	errInvalidAPIKey        = errors.New("invalid or revoked api key")
	errUnsupportedGrant     = errors.New("unsupported grant_type")
)

type AuthHandler struct {
	poolMgr    *pool.Manager
	jwtService *auth.JWTService
	accessExp  int // seconds — access token lifetime returned in expires_in
	refreshExp int // seconds
}

func NewAuthHandler(poolMgr *pool.Manager, jwtService *auth.JWTService, accessExp, refreshExp int) *AuthHandler {
	return &AuthHandler{poolMgr: poolMgr, jwtService: jwtService, accessExp: accessExp, refreshExp: refreshExp}
}

func (h *AuthHandler) Routes(r chi.Router) {
	r.Route("/{orgSlug}/{projectId}", func(r chi.Router) {
		r.Use(middleware.TenantContext)
		r.Post("/register", h.Register)
		r.Post("/login", h.Login)
		r.Post("/validate", h.Validate)
		r.Post("/refresh", h.Refresh)
		r.Post("/logout", h.Logout)
		// OAuth2-shaped unified endpoint. Legacy routes above still work and
		// share the same exchange helpers — no HTTP re-dispatch.
		r.Post("/token", h.Token)

		// API key management — protected by JWT. Mounting RequireJWT here at
		// the route registration site (instead of inside apikey.go) makes the
		// auth requirement impossible to forget.
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireJWT(h.jwtService))
			r.Route("/api-keys", h.APIKeyRoutes)
		})
	})
}

// projectKey returns the opaque projectId used as pool key and vault path segment.
// Globally unique (provisioning mints it), so org scoping is handled by URL path, not the key.
func projectKey(r *http.Request) string {
	pid := chi.URLParam(r, "projectId")
	log.Printf("SENTINEL_RENAME_V3 projectKey returning projectId=%q orgSlug=%q", pid, chi.URLParam(r, "orgSlug"))
	return pid
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	projectID := projectKey(r)
	tenantID, _ := middleware.TenantIDFromContext(r.Context())
	orgSlug, _ := middleware.OrgSlugFromContext(r.Context())
	var req domain.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "invalid request", 400)
		return
	}
	if req.Email == "" || req.Password == "" || req.FullName == "" {
		httpError(w, "email, password, and fullName are required", 400)
		return
	}

	log.Printf("auth.register tenant=%s org=%s email=%s", tenantID, orgSlug, req.Email)

	pool, err := h.poolMgr.GetPool(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		httpError(w, "failed to connect to project database", 503)
		return
	}

	// Check if email exists
	var exists bool
	pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", req.Email).Scan(&exists)
	if exists {
		httpError(w, "email already registered", 409)
		return
	}

	// Hash password
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		httpError(w, "internal error", 500)
		return
	}

	// Insert user
	var userID int64
	err = pool.QueryRow(r.Context(),
		`INSERT INTO users (email, password, full_name, role, enabled, created_at, updated_at)
		 VALUES ($1, $2, $3, 'user', true, NOW(), NOW()) RETURNING id`,
		req.Email, hash, req.FullName,
	).Scan(&userID)
	if err != nil {
		httpError(w, "failed to create user", 500)
		return
	}

	resp, err := h.generateAuthResponse(r, projectID, userID, req.Email, req.FullName)
	if err != nil {
		httpError(w, "failed to generate tokens", 500)
		return
	}

	w.WriteHeader(201)
	writeJSON(w, resp)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	projectID := projectKey(r)
	tenantID, _ := middleware.TenantIDFromContext(r.Context())
	orgSlug, _ := middleware.OrgSlugFromContext(r.Context())
	var req domain.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "invalid request", 400)
		return
	}
	log.Printf("auth.login tenant=%s org=%s email=%s", tenantID, orgSlug, req.Email)
	resp, code, err := h.exchangePassword(r, projectID, req.Email, req.Password)
	if err != nil {
		log.Printf("auth.login.fail tenant=%s org=%s email=%s code=%d err=%v", tenantID, orgSlug, req.Email, code, err)
		httpError(w, err.Error(), code)
		return
	}
	writeJSON(w, resp)
}

// exchangePassword authenticates a user by email/password and returns a fresh
// AuthResponse. Returns (nil, statusCode, err) on failure.
func (h *AuthHandler) exchangePassword(r *http.Request, projectID, email, password string) (*domain.AuthResponse, int, error) {
	pool, err := h.poolMgr.GetPool(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		return nil, 503, errProjectDBUnavailable
	}

	var user domain.User
	err = pool.QueryRow(r.Context(),
		"SELECT id, email, password, full_name, role, enabled FROM users WHERE email = $1",
		email,
	).Scan(&user.ID, &user.Email, &user.Password, &user.FullName, &user.Role, &user.Enabled)
	if err != nil {
		return nil, 401, errInvalidCredentials
	}
	if !user.Enabled {
		return nil, 403, errAccountDisabled
	}
	if !auth.CheckPassword(password, user.Password) {
		return nil, 401, errInvalidCredentials
	}

	pool.Exec(r.Context(), "UPDATE users SET last_login_at = NOW() WHERE id = $1", user.ID)

	resp, err := h.generateAuthResponse(r, projectID, user.ID, user.Email, user.FullName)
	if err != nil {
		return nil, 500, errTokenGeneration
	}
	return resp, 200, nil
}

func (h *AuthHandler) Validate(w http.ResponseWriter, r *http.Request) {
	var req domain.ValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "invalid request", 400)
		return
	}

	claims, err := h.jwtService.Verify(req.Token)
	if err != nil {
		writeJSON(w, map[string]interface{}{"valid": false, "error": err.Error()})
		return
	}

	writeJSON(w, map[string]interface{}{
		"valid":     true,
		"email":     claims.Sub,
		"userId":    claims.UserID,
		"projectId": claims.ProjectID,
		"role":      claims.Role,
	})
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	projectID := projectKey(r)
	var req domain.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "invalid request", 400)
		return
	}
	resp, code, err := h.exchangeRefreshToken(r, projectID, req.RefreshToken)
	if err != nil {
		httpError(w, err.Error(), code)
		return
	}
	writeJSON(w, resp)
}

// exchangeRefreshToken validates a refresh token, revokes it (rotation), and
// returns a fresh AuthResponse for the same user. Returns (nil, statusCode, err)
// on failure.
func (h *AuthHandler) exchangeRefreshToken(r *http.Request, projectID, refreshToken string) (*domain.AuthResponse, int, error) {
	pool, err := h.poolMgr.GetPool(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		return nil, 503, errProjectDBUnavailable
	}

	var tokenID, userID int64
	var revoked bool
	var expiryDate time.Time
	err = pool.QueryRow(r.Context(),
		"SELECT id, user_id, revoked, expiry_date FROM refresh_tokens WHERE token = $1",
		refreshToken,
	).Scan(&tokenID, &userID, &revoked, &expiryDate)
	if err != nil {
		return nil, 401, errInvalidRefreshToken
	}
	if revoked {
		return nil, 401, errRefreshTokenRevoked
	}
	if time.Now().After(expiryDate) {
		return nil, 401, errRefreshTokenExpired
	}

	pool.Exec(r.Context(), "UPDATE refresh_tokens SET revoked = true WHERE id = $1", tokenID)

	var email, fullName string
	if err := pool.QueryRow(r.Context(),
		"SELECT email, full_name FROM users WHERE id = $1", userID,
	).Scan(&email, &fullName); err != nil {
		// Refresh token row exists but the underlying user is gone (CASCADE
		// should normally clean these up, but defend against drift). Treat as
		// invalid rather than minting a JWT for a ghost user.
		return nil, 401, errInvalidRefreshToken
	}

	resp, err := h.generateAuthResponse(r, projectID, userID, email, fullName)
	if err != nil {
		return nil, 500, errTokenGeneration
	}
	return resp, 200, nil
}

// exchangeAPIKey validates an opaque API key (esk_pub_live_… / esk_sec_live_…),
// updates last_used_at, and issues a JWT keyed to the project. The api_key flow
// does NOT issue a refresh token — the api key itself is the long-lived
// credential and clients re-exchange via grant_type=api_key when the JWT expires.
//
// Note on timing: the lookup uses Postgres `=` on a VARCHAR which is not
// guaranteed constant-time. Because api keys carry ~143 bits of entropy from
// crypto/rand, brute force is infeasible regardless and the residual timing
// channel is theoretical. If this ever moves to a high-throughput hot path,
// switch to a HMAC-keyed lookup with a constant-time server-side comparison.
func (h *AuthHandler) exchangeAPIKey(r *http.Request, projectID, apiKey string) (*domain.AuthResponse, int, error) {
	if apiKey == "" {
		return nil, 400, errMissingAPIKey
	}
	pool, err := h.poolMgr.GetPool(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		return nil, 503, errProjectDBUnavailable
	}

	hash := service.HashAPIKey(apiKey)
	var (
		keyID     int64
		keyType   string
		createdBy *int64
	)
	err = pool.QueryRow(r.Context(),
		"SELECT id, key_type, created_by FROM auth.api_keys WHERE key_hash = $1 AND revoked_at IS NULL",
		hash,
	).Scan(&keyID, &keyType, &createdBy)
	if err != nil {
		return nil, 401, errInvalidAPIKey
	}

	pool.Exec(r.Context(), "UPDATE auth.api_keys SET last_used_at = NOW() WHERE id = $1", keyID)

	var userID int64
	if createdBy != nil {
		userID = *createdBy
	}
	resp, err := h.generateAPIKeyAuthResponse(r, projectID, userID, keyID, keyType)
	if err != nil {
		return nil, 500, errTokenGeneration
	}
	return resp, 200, nil
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	projectID := projectKey(r)
	var req domain.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "invalid request", 400)
		return
	}

	pool, err := h.poolMgr.GetPool(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		httpError(w, "failed to connect to project database", 503)
		return
	}

	pool.Exec(r.Context(), "UPDATE refresh_tokens SET revoked = true WHERE token = $1", req.RefreshToken)
	writeJSON(w, map[string]string{"message": "Logged out successfully"})
}

func (h *AuthHandler) generateAuthResponse(r *http.Request, projectID string, userID int64, email, fullName string) (*domain.AuthResponse, error) {
	orgSlug := chi.URLParam(r, "orgSlug")

	// Look up display names from provisioning (cached per projectId in poolMgr).
	// Best-effort — if provisioning is unreachable, fall back to projectId/orgSlug
	// so we never block login on a metadata lookup.
	projectName := projectID
	orgName := orgSlug
	if info, err := h.poolMgr.GetProjectInfo(r.Context(), projectID); err == nil {
		if info.ProjectName != "" {
			projectName = info.ProjectName
		}
		if info.OrgName != "" {
			orgName = info.OrgName
		}
		if info.OrgSlug != "" {
			orgSlug = info.OrgSlug
		}
	}

	accessToken, err := h.jwtService.Sign(auth.Claims{
		Sub:         email,
		UserID:      userID,
		ProjectID:   projectID,
		OrgSlug:     orgSlug,
		ProjectName: projectName,
		OrgName:     orgName,
		Role:        "user",
		// Password-flow tokens are end-user identities. Edge functions branch
		// on this header (X-Excalibase-Scope) to distinguish anon traffic
		// (scope=public via service-key flow) from logged-in users.
		Scope: "authenticated",
	})
	if err != nil {
		return nil, err
	}

	refreshToken := uuid.New().String()
	expiryDate := time.Now().Add(time.Duration(h.refreshExp) * time.Second)

	pool, _ := h.poolMgr.GetPool(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if pool != nil {
		pool.Exec(r.Context(),
			"INSERT INTO refresh_tokens (token, user_id, expiry_date, created_at, revoked) VALUES ($1, $2, $3, NOW(), false)",
			refreshToken, userID, expiryDate,
		)
	}

	return &domain.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(h.accessExp),
		User:         domain.UserInfo{ID: userID, Email: email, FullName: fullName},
	}, nil
}

// generateAPIKeyAuthResponse issues a JWT for an api-key grant. It does not
// create a refresh token: the api key itself is the long-lived credential.
//
// The token's `sub` is set to "apikey:<id>" so downstream consumers can
// distinguish api-key tokens from user-password tokens at a glance, and the
// `role` reflects the key type (publishable → "user", secret → "service") so
// authorization checks have something coarser than scope to act on.
func (h *AuthHandler) generateAPIKeyAuthResponse(r *http.Request, projectID string, userID, keyID int64, keyType string) (*domain.AuthResponse, error) {
	orgSlug := chi.URLParam(r, "orgSlug")

	projectName := projectID
	orgName := orgSlug
	if info, err := h.poolMgr.GetProjectInfo(r.Context(), projectID); err == nil {
		if info.ProjectName != "" {
			projectName = info.ProjectName
		}
		if info.OrgName != "" {
			orgName = info.OrgName
		}
		if info.OrgSlug != "" {
			orgSlug = info.OrgSlug
		}
	}

	scope := "public"
	role := "user"
	if keyType == string(service.KeyTypeSecret) {
		scope = "service"
		role = "service"
	}

	accessToken, err := h.jwtService.Sign(auth.Claims{
		Sub:         fmt.Sprintf("apikey:%d", keyID),
		UserID:      userID,
		ProjectID:   projectID,
		OrgSlug:     orgSlug,
		ProjectName: projectName,
		OrgName:     orgName,
		Role:        role,
		Scope:       scope,
		KeyID:       keyID,
	})
	if err != nil {
		return nil, err
	}
	return &domain.AuthResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(h.accessExp),
	}, nil
}

// Token is the OAuth2-shaped unified entrypoint. It dispatches on grant_type
// to the same exchange helpers used by the legacy /login, /refresh endpoints,
// plus the new api_key flow.
func (h *AuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	projectID := projectKey(r)
	var req domain.TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "invalid request", 400)
		return
	}

	var (
		resp *domain.AuthResponse
		code int
		err  error
	)
	switch req.GrantType {
	case "password":
		resp, code, err = h.exchangePassword(r, projectID, req.Email, req.Password)
	case "api_key":
		resp, code, err = h.exchangeAPIKey(r, projectID, req.APIKey)
	case "refresh_token":
		resp, code, err = h.exchangeRefreshToken(r, projectID, req.RefreshToken)
	default:
		httpError(w, errUnsupportedGrant.Error(), 400)
		return
	}
	if err != nil {
		httpError(w, err.Error(), code)
		return
	}
	writeJSON(w, resp)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":  msg,
		"status": code,
	})
}
