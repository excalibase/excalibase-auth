package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/pool"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	poolMgr    *pool.Manager
	jwtService *auth.JWTService
	refreshExp int // seconds
}

func NewAuthHandler(poolMgr *pool.Manager, jwtService *auth.JWTService, refreshExp int) *AuthHandler {
	return &AuthHandler{poolMgr: poolMgr, jwtService: jwtService, refreshExp: refreshExp}
}

func (h *AuthHandler) Routes(r chi.Router) {
	r.Route("/{orgSlug}/{projectName}", func(r chi.Router) {
		r.Post("/register", h.Register)
		r.Post("/login", h.Login)
		r.Post("/validate", h.Validate)
		r.Post("/refresh", h.Refresh)
		r.Post("/logout", h.Logout)
	})
}

// projectKey returns "{orgSlug}/{projectName}" used as pool key and vault path segment.
func projectKey(r *http.Request) string {
	return chi.URLParam(r, "orgSlug") + "/" + chi.URLParam(r, "projectName")
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	projectID := projectKey(r)
	var req domain.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "invalid request", 400)
		return
	}
	if req.Email == "" || req.Password == "" || req.FullName == "" {
		httpError(w, "email, password, and fullName are required", 400)
		return
	}

	pool, err := h.poolMgr.GetPool(r.Context(), projectID)
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
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		httpError(w, "internal error", 500)
		return
	}

	// Insert user
	var userID int64
	err = pool.QueryRow(r.Context(),
		`INSERT INTO users (email, password, full_name, role, enabled, created_at, updated_at)
		 VALUES ($1, $2, $3, 'user', true, NOW(), NOW()) RETURNING id`,
		req.Email, string(hash), req.FullName,
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
	var req domain.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "invalid request", 400)
		return
	}

	pool, err := h.poolMgr.GetPool(r.Context(), projectID)
	if err != nil {
		httpError(w, "failed to connect to project database", 503)
		return
	}

	var user domain.User
	err = pool.QueryRow(r.Context(),
		"SELECT id, email, password, full_name, role, enabled FROM users WHERE email = $1",
		req.Email,
	).Scan(&user.ID, &user.Email, &user.Password, &user.FullName, &user.Role, &user.Enabled)
	if err != nil {
		httpError(w, "invalid email or password", 401)
		return
	}

	if !user.Enabled {
		httpError(w, "account is disabled", 403)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		httpError(w, "invalid email or password", 401)
		return
	}

	// Update last login
	pool.Exec(r.Context(), "UPDATE users SET last_login_at = NOW() WHERE id = $1", user.ID)

	resp, err := h.generateAuthResponse(r, projectID, user.ID, user.Email, user.FullName)
	if err != nil {
		httpError(w, "failed to generate tokens", 500)
		return
	}

	writeJSON(w, resp)
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

	pool, err := h.poolMgr.GetPool(r.Context(), projectID)
	if err != nil {
		httpError(w, "failed to connect to project database", 503)
		return
	}

	// Verify refresh token
	var tokenID, userID int64
	var revoked bool
	var expiryDate time.Time
	err = pool.QueryRow(r.Context(),
		"SELECT id, user_id, revoked, expiry_date FROM refresh_tokens WHERE token = $1",
		req.RefreshToken,
	).Scan(&tokenID, &userID, &revoked, &expiryDate)
	if err != nil {
		httpError(w, "invalid refresh token", 401)
		return
	}
	if revoked {
		httpError(w, "refresh token revoked", 401)
		return
	}
	if time.Now().After(expiryDate) {
		httpError(w, "refresh token expired", 401)
		return
	}

	// Revoke old token
	pool.Exec(r.Context(), "UPDATE refresh_tokens SET revoked = true WHERE id = $1", tokenID)

	// Get user info
	var email, fullName string
	pool.QueryRow(r.Context(), "SELECT email, full_name FROM users WHERE id = $1", userID).Scan(&email, &fullName)

	resp, err := h.generateAuthResponse(r, projectID, userID, email, fullName)
	if err != nil {
		httpError(w, "failed to generate tokens", 500)
		return
	}

	writeJSON(w, resp)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	projectID := projectKey(r)
	var req domain.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "invalid request", 400)
		return
	}

	pool, err := h.poolMgr.GetPool(r.Context(), projectID)
	if err != nil {
		httpError(w, "failed to connect to project database", 503)
		return
	}

	pool.Exec(r.Context(), "UPDATE refresh_tokens SET revoked = true WHERE token = $1", req.RefreshToken)
	writeJSON(w, map[string]string{"message": "Logged out successfully"})
}

func (h *AuthHandler) generateAuthResponse(r *http.Request, projectID string, userID int64, email, fullName string) (*domain.AuthResponse, error) {
	orgSlug := chi.URLParam(r, "orgSlug")
	projectName := chi.URLParam(r, "projectName")

	accessToken, err := h.jwtService.Sign(auth.Claims{
		Sub:         email,
		UserID:      userID,
		ProjectID:   projectID,
		OrgSlug:     orgSlug,
		ProjectName: projectName,
		Role:        "user",
	})
	if err != nil {
		return nil, err
	}

	refreshToken := uuid.New().String()
	expiryDate := time.Now().Add(time.Duration(h.refreshExp) * time.Second)

	pool, _ := h.poolMgr.GetPool(r.Context(), projectID)
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
		ExpiresIn:    3600,
		User:         domain.UserInfo{ID: userID, Email: email, FullName: fullName},
	}, nil
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
