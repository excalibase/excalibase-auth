package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/domain"
	"github.com/excalibase/auth/internal/email"
	"github.com/excalibase/auth/internal/metrics"
	"github.com/excalibase/auth/internal/middleware"
	"github.com/excalibase/auth/internal/oauth"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/requestmetrics"
	"github.com/excalibase/auth/internal/service"
	"github.com/excalibase/auth/internal/store"
	"github.com/excalibase/auth/internal/throttle"
	"github.com/excalibase/auth/internal/token"
	"github.com/go-chi/chi/v5"
)

// Shared sentinel errors so HTTP handlers and the unified /token dispatch
// surface identical messages.
var (
	errProjectDBUnavailable = errors.New("failed to connect to project database")
	errProjectHasNoDatabase = errors.New("project has no database")
	errInvalidCredentials   = errors.New("invalid email or password")
	errAccountDisabled      = errors.New("account is disabled")
	errInvalidRefreshToken  = errors.New("invalid refresh token")
	errRefreshTokenRevoked  = errors.New("refresh token revoked")
	errRefreshTokenExpired  = errors.New("refresh token expired")
	errTokenGeneration      = errors.New("failed to generate tokens")
	errMissingAPIKey        = errors.New("api_key is required")
	errInvalidAPIKey        = errors.New("invalid or revoked api key")
	errUnsupportedGrant     = errors.New("unsupported grant_type")
	errHashingBusy          = errors.New("server busy, retry shortly")
	errEmailAndNameRequired = errors.New("email and fullName are required")
	errCannotRegister       = errors.New("cannot register with this email; sign in or reset the password")
)

// passwordHasher bounds how many argon2id hashes run at once; a saturated
// hasher answers auth.ErrHashBusy rather than risking the pod's memory.
type passwordHasher interface {
	Hash(ctx context.Context, password string) (string, error)
	Check(ctx context.Context, password, encoded string) (bool, error)
}

// verificationSentMessage is the single answer /resend-verification gives for
// every address, whether or not an account exists behind it.
const verificationSentMessage = "If the account exists and is unverified, a verification email has been sent"

type AuthHandler struct {
	poolMgr    *pool.Manager
	jwtService *auth.JWTService
	refreshExp int                    // seconds
	limits     *middleware.RateLimits // nil disables throttling
	// trustedProxies are the peers whose X-Forwarded-For is believed; none by default.
	trustedProxies []*net.IPNet

	emailSender    email.Sender
	siteURL        string // fallback base for email links (AUTH_SITE_URL)
	resendThrottle *throttle.Throttle
	forgotThrottle *throttle.Throttle
	hasher         passwordHasher

	// corsPlatform (Studio) and corsOrigins (the project's allowlist) answer
	// CORS on project routes; with no source no project origin is granted.
	corsPlatform []string
	corsOrigins  middleware.OriginResolver

	requestMetrics *requestmetrics.Recorder // nil when the request charts are off

	// Provider sign-in (EXC-662): on for a project only when /info lists it.
	oauthProviders map[string]oauth.Provider
	oauthHTTP      *http.Client
	signInMaxAge   time.Duration

	// Sign-in by emailed link or code (EXC-662); otpKey is nil, and the
	// routes unavailable, if it could not be derived.
	otpKey       []byte
	otpLimits    store.OTPLimits
	dispatchMail func(send func())

	// Account self-service (EXC-662): on for a project only when /info says so.
	emailChangeLimits store.EmailChangeLimits

	// Guest accounts (EXC-662): on for a project only when /info says so.
	guestLimits        store.GuestLimits
	captchaVerifyURL   string
	guestInactiveAfter time.Duration

	// TOTP second factors (EXC-662): on for a project only when /info says so.
	mfaLimits store.MFALimits
}

func NewAuthHandler(poolMgr *pool.Manager, jwtService *auth.JWTService, refreshExp int) *AuthHandler {
	h := &AuthHandler{
		poolMgr:    poolMgr,
		jwtService: jwtService,
		refreshExp: refreshExp,
		// Default to dropping mail so a deployment without an email path still
		// registers users rather than failing closed on an unset dependency.
		emailSender:        email.NoopSender{},
		resendThrottle:     throttle.New(resendVerificationLimit, resendVerificationWindow),
		forgotThrottle:     throttle.New(forgotPasswordLimit, forgotPasswordWindow),
		hasher:             auth.NewHasher(auth.DefaultHashSlots, auth.DefaultHashWait),
		oauthProviders:     defaultOAuthProviders(),
		oauthHTTP:          &http.Client{Timeout: providerTimeout},
		signInMaxAge:       defaultSignInMaxAge,
		otpLimits:          defaultOTPLimits,
		emailChangeLimits:  defaultEmailChangeLimits,
		guestLimits:        defaultGuestLimits,
		captchaVerifyURL:   turnstileVerifyURL,
		guestInactiveAfter: DefaultGuestInactiveDays * 24 * time.Hour,
		mfaLimits:          defaultMFALimits,
		dispatchMail:       func(send func()) { go send() },
	}
	if jwtService != nil {
		key, err := jwtService.DerivedKey(otpKeyPurpose)
		if err != nil {
			log.Printf("auth.otp.key_unavailable: email sign-in is off: %v", err)
		}
		h.otpKey = key
	}
	return h
}

// WithHasher replaces the bounded password hasher.
func (h *AuthHandler) WithHasher(hasher passwordHasher) *AuthHandler {
	h.hasher = hasher
	return h
}

// SetEmail wires the transactional mailer and the fallback site URL used to
// build links when a project carries no site URL of its own.
func (h *AuthHandler) SetEmail(sender email.Sender, siteURL string) {
	if sender != nil {
		h.emailSender = sender
	}
	h.siteURL = normalizeSiteURL(siteURL)
}

// WithCORS sets who may call project routes from a browser: the platform's
// own origins plus each project's allowlist, read through origins.
func (h *AuthHandler) WithCORS(platformOrigins []string, origins middleware.OriginResolver) *AuthHandler {
	h.corsPlatform = append([]string{}, platformOrigins...)
	h.corsOrigins = origins
	return h
}

// WithRequestMetrics counts every project route's calls for the request charts.
func (h *AuthHandler) WithRequestMetrics(recorder *requestmetrics.Recorder) *AuthHandler {
	h.requestMetrics = recorder
	return h
}

// WithRateLimits enables throttling of the credential routes. It returns the
// receiver so construction reads as a chain.
func (h *AuthHandler) WithRateLimits(limits *middleware.RateLimits) *AuthHandler {
	h.limits = limits
	return h
}

func (h *AuthHandler) Routes(r chi.Router) {
	// The token-signing public keys, under the prefix the edge routes, so a
	// customer backend verifies end-user tokens offline (EXC-600).
	r.Get("/.well-known/jwks.json", h.JWKS)
	r.Route("/{orgSlug}/{projectId}", func(r chi.Router) {
		if h.requestMetrics != nil {
			r.Use(h.requestMetrics.Middleware)
		}
		r.Use(middleware.ProjectCORS(h.corsPlatform, h.corsOrigins))
		r.Use(middleware.TenantContext)
		r.Get("/.well-known/jwks.json", h.JWKS)
		r.With(h.limit(rateLimitRegister)).Post("/register", h.Register)
		// Guest accounts (EXC-662); a project without them answers 404.
		r.With(h.limit(rateLimitGuest)).Post("/guest", h.SignInAsGuest)
		r.With(h.limit(rateLimitLogin)).Post("/login", h.Login)
		r.Post("/validate", h.Validate)
		// /refresh is the legacy alias of grant_type=refresh_token, so it
		// draws from the same per-IP budget as /token.
		r.With(h.limit(rateLimitToken)).Post("/refresh", h.Refresh)
		r.Post("/logout", h.Logout)
		// Email verification (EXC-11). GET serves the link in the email; POST
		// serves front ends that post the token themselves.
		r.Get("/verify-email", h.VerifyEmail)
		r.Post("/verify-email", h.VerifyEmail)
		r.Post("/resend-verification", h.ResendVerification)
		// Password reset (EXC-12).
		r.Post("/forgot-password", h.ForgotPassword)
		r.Post("/reset-password", h.ResetPassword)
		// OAuth2-shaped unified endpoint. Legacy routes above still work and
		// share the same exchange helpers — no HTTP re-dispatch.
		r.With(h.limit(rateLimitToken)).Post("/token", h.Token)
		// Provider sign-in (EXC-662); a project without providers answers 404.
		r.With(h.limit(rateLimitToken)).Get("/authorize", h.Authorize)
		r.With(h.limit(rateLimitToken)).Get("/callback/{provider}", h.Callback)
		// Emailed link or code (EXC-662); a project without it answers 404.
		r.With(h.limit(rateLimitOTP)).Post("/otp", h.SendOTP)
		r.With(h.limit(rateLimitToken)).Post("/verify", h.VerifyOTP)

		// A signed-in end user's identities and own account (EXC-662); each
		// answers 404 while its method is off for the project.
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireJWT(h.jwtService))
			r.Route("/user/identities", h.IdentityRoutes)
		})
		r.Group(func(r chi.Router) {
			r.Use(h.requireUserAPI, middleware.RequireJWT(h.jwtService), requireEndUser)
			r.Get("/user", h.GetUser)
			r.With(h.limit(rateLimitToken)).Patch("/user", h.UpdateUser)
			r.With(h.limit(rateLimitToken)).Post("/user/email/confirm", h.ConfirmEmailChange)
		})
		h.mfaRoutes(r)

		// API key management — protected by JWT. Mounting RequireJWT here at
		// the route registration site (instead of inside apikey.go) makes the
		// auth requirement impossible to forget.
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireJWT(h.jwtService))
			r.Route("/api-keys", h.APIKeyRoutes)
		})

		// End-user roles (EXC-370): only the control plane's user-admin token
		// or the project's secret-key token, checked here at registration.
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireJWT(h.jwtService))
			r.Use(requireUserManager)
			r.Route("/users", h.UserRoutes)
		})
	})
}

// rateLimitRoute selects one of the RateLimits middlewares by method
// expression so Routes can stay declarative.
type rateLimitRoute func(*middleware.RateLimits, http.Handler) http.Handler

var (
	rateLimitRegister rateLimitRoute = (*middleware.RateLimits).Register
	rateLimitGuest    rateLimitRoute = (*middleware.RateLimits).Guest
	rateLimitLogin    rateLimitRoute = (*middleware.RateLimits).Login
	rateLimitToken    rateLimitRoute = (*middleware.RateLimits).Token
	rateLimitOTP      rateLimitRoute = (*middleware.RateLimits).OTP
)

// limit returns the chosen limiter middleware, or a pass-through when
// throttling is disabled.
func (h *AuthHandler) limit(route rateLimitRoute) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if h.limits == nil {
			return next
		}
		return route(h.limits, next)
	}
}

// WithTrustedProxies sets the proxies whose X-Forwarded-For header the handler's
// own per-IP throttles believe.
func (h *AuthHandler) WithTrustedProxies(trusted []*net.IPNet) *AuthHandler {
	h.trustedProxies = trusted
	return h
}

// projectKey returns the opaque projectId used as pool key and vault path segment.
// Globally unique (provisioning mints it), so org scoping is handled by URL path, not the key.
func projectKey(r *http.Request) string {
	return chi.URLParam(r, "projectId")
}

// registerAcceptedMessage is the one answer a verification-required sign-up
// gives, whether the address was new or already had an account.
const registerAcceptedMessage = "Check your email to confirm your address, then sign in"

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	projectID := projectKey(r)
	tenantID, _ := middleware.TenantIDFromContext(r.Context())
	orgSlug, _ := middleware.OrgSlugFromContext(r.Context())
	req, ok := decodeRegisterRequest(w, r)
	if !ok {
		return
	}

	if open, err := h.signupsOpen(r.Context(), projectID); err != nil {
		httpError(w, errSettingsUnreadable, http.StatusServiceUnavailable)
		return
	} else if !open {
		httpError(w, errSignupDisabled.Error(), http.StatusForbidden)
		return
	}
	settings := h.settingsFor(r.Context(), projectID)
	if settings.requireEmailVerification && settings.siteURL == "" {
		writeSiteURLRequired(w, projectID)
		return
	}

	log.Printf("auth.register tenant=%s org=%s email=%s", safeLog(tenantID), safeLog(orgSlug), safeLog(req.Email))

	db, err := h.poolMgr.GetStore(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		writePoolFailure(w, err)
		return
	}

	// Hashed before the insert, so a taken address costs the same time as a new one.
	hash, err := h.hasher.Hash(r.Context(), req.Password)
	if err != nil {
		writeHashFailure(w, err)
		return
	}
	user, role, created, err := insertUser(r.Context(), db, req, hash)
	if err != nil {
		httpError(w, "failed to create user", 500)
		return
	}

	if settings.requireEmailVerification {
		if created {
			metrics.Signups.Inc()
			h.sendVerification(r.Context(), db, projectID, user.ID, req.Email, settings.siteURL, true)
		} else {
			h.replaceUnverified(r.Context(), db, projectID, req, hash, settings.siteURL)
		}
		writeRegisterAccepted(w, req)
		return
	}
	if !created {
		// Sign-up signs the user in here, so a taken address cannot be hidden
		// without a new flow; the message at least names no account.
		httpError(w, errCannotRegister.Error(), 409)
		return
	}
	metrics.Signups.Inc()

	resp, err := h.generateAuthResponse(r, projectID, user, accountRoles{role: role}, false, methodPassword)
	if err != nil {
		httpError(w, "failed to generate tokens", 500)
		return
	}
	w.WriteHeader(201)
	writeJSON(w, resp)
}

// decodeRegisterRequest answers 400 for a body that is malformed, incomplete
// or whose password breaks the policy.
func decodeRegisterRequest(w http.ResponseWriter, r *http.Request) (domain.RegisterRequest, bool) {
	var req domain.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "invalid request", 400)
		return req, false
	}
	if req.Email == "" || req.FullName == "" {
		httpError(w, errEmailAndNameRequired.Error(), 400)
		return req, false
	}
	if err := validatePassword(req.Password); err != nil {
		httpError(w, err.Error(), 400)
		return req, false
	}
	return req, true
}

// defaultAccountRole is the role every new account is created with.
const defaultAccountRole = "user"

// insertUser creates the account unless the address is taken, reporting which.
func insertUser(ctx context.Context, db store.Store, req domain.RegisterRequest, hash string) (domain.UserInfo, string, bool, error) {
	user := domain.UserInfo{Email: req.Email, FullName: req.FullName}
	id, created, err := db.InsertUser(ctx, req.Email, hash, req.FullName)
	if err != nil || !created {
		return user, "", false, err
	}
	user.ID = id
	return user, defaultAccountRole, true, nil
}

// replaceUnverified lets a sign-up for an address nobody has proved take the
// account over: the newest sign-up's password and name win and only its link
// stays live, so whoever owns the inbox ends up with the password they chose.
// It shares the resend budget per address; past it the sign-up changes nothing.
func (h *AuthHandler) replaceUnverified(ctx context.Context, db store.Store, projectID string, req domain.RegisterRequest, hash, siteURL string) {
	if !h.resendThrottle.Allow(token.Hash(projectID + "|" + req.Email)) {
		return
	}
	userID, err := db.ReplaceUnverified(ctx, req.Email, hash, req.FullName)
	if err != nil {
		return
	}
	if err := db.RevokeUserRefreshTokens(ctx, userID); err != nil {
		log.Printf("auth.register.revoke_failed project=%s userId=%d", safeLog(projectID), userID)
	}
	h.sendVerification(ctx, db, projectID, userID, req.Email, siteURL, true)
}

// writeRegisterAccepted answers a verification-required sign-up. It carries
// only what the caller sent, so a new and an existing address read the same.
func writeRegisterAccepted(w http.ResponseWriter, req domain.RegisterRequest) {
	w.WriteHeader(201)
	writeJSON(w, map[string]interface{}{
		"emailVerificationRequired": true,
		"message":                   registerAcceptedMessage,
		"user":                      map[string]string{"email": req.Email, "fullName": req.FullName},
	})
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
	log.Printf("auth.login tenant=%s org=%s email=%s", safeLog(tenantID), safeLog(orgSlug), safeLog(req.Email))
	resp, code, err := h.exchangePassword(r, projectID, req.Email, req.Password)
	if err != nil {
		metrics.LoginFailures.Inc()
		log.Printf("auth.login.fail tenant=%s org=%s email=%s code=%d err=%v", safeLog(tenantID), safeLog(orgSlug), safeLog(req.Email), code, err)
		writeError(w, err, code)
		return
	}
	metrics.Logins.Inc()
	writeJSON(w, resp)
}

// exchangePassword authenticates a user by email/password and returns a fresh
// AuthResponse. Returns (nil, statusCode, err) on failure.
func (h *AuthHandler) exchangePassword(r *http.Request, projectID, email, password string) (*domain.AuthResponse, int, error) {
	db, err := h.poolMgr.GetStore(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		status, perr := poolFailure(err)
		return nil, status, perr
	}

	user, err := db.AccountByEmail(r.Context(), email)
	if err != nil {
		return nil, 401, errInvalidCredentials
	}
	if !user.Enabled {
		return nil, 403, errAccountDisabled
	}
	matched, err := h.checkPassword(r.Context(), password, user.PasswordHash)
	if err != nil {
		return nil, 503, errHashingBusy
	}
	if !matched {
		return nil, 401, errInvalidCredentials
	}
	// EXC-11: checked only after the password, so this never tells an
	// unauthenticated caller whether an address is registered.
	if !user.EmailVerified && h.settingsFor(r.Context(), projectID).requireEmailVerification {
		return nil, 403, errEmailNotVerified
	}
	roles := accountRoles{role: user.Role, allowed: user.AllowedRoles}
	if err := roles.validate(); err != nil {
		return nil, 403, err
	}

	_ = db.TouchLastLogin(r.Context(), user.ID)

	resp, err := h.generateAuthResponse(r, projectID, userInfoOf(user), roles, user.EmailVerified, methodPassword)
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
	if !claims.IsAccess() {
		writeJSON(w, map[string]interface{}{"valid": false, "error": "not an access token"})
		return
	}

	// Bind the token to the project in the URL. A signature-valid token for
	// project A must not validate against project B's endpoint — otherwise
	// /validate becomes a cross-project oracle.
	if claims.ProjectID != projectKey(r) {
		writeJSON(w, map[string]interface{}{"valid": false, "error": "token project mismatch"})
		return
	}

	result := map[string]interface{}{
		"valid":     true,
		"sub":       claims.Sub,
		"projectId": claims.ProjectID,
		"role":      claims.Role,
	}
	if claims.Email != "" {
		result["email"] = claims.Email
	}
	if claims.UserID != 0 {
		result["userId"] = claims.UserID
	}
	writeJSON(w, result)
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

// exchangeRefreshToken rotates a refresh token: the presented one is revoked
// and a successor in the same session is issued with a fresh access token.
func (h *AuthHandler) exchangeRefreshToken(r *http.Request, projectID, refreshToken string) (*domain.AuthResponse, int, error) {
	ctx := r.Context()
	db, err := h.poolMgr.GetStore(ctx, chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		status, perr := poolFailure(err)
		return nil, status, perr
	}
	hash := token.Hash(refreshToken)
	successor, successorHash, err := token.New()
	if err != nil {
		return nil, 500, errRefreshTokenStore
	}

	var roles accountRoles
	// A refusal returns before the store commits, so the token survives it.
	account, session, err := db.RotateRefreshToken(ctx, hash, successorHash, func(account store.Account) error {
		var err error
		roles, err = h.refreshAllowed(ctx, projectID, account)
		return err
	})
	var refusal refreshRefusal
	switch {
	case errors.Is(err, store.ErrNotFound):
		code, rejectErr := rejectDeadRefreshToken(ctx, db, hash)
		return nil, code, rejectErr
	case errors.Is(err, store.ErrNoAccount):
		return nil, 401, errInvalidRefreshToken
	case errors.As(err, &refusal):
		return nil, refusal.status, refusal.err
	case errors.Is(err, store.ErrUnavailable):
		return nil, 503, errProjectDBUnavailable
	case err != nil:
		return nil, 500, errRefreshTokenStore
	}

	resp, err := h.sessionResponse(r, projectID, userInfoOf(account), roles, account.EmailVerified, successor, session)
	if err != nil {
		return nil, 500, errTokenGeneration
	}
	return resp, 200, nil
}

// refreshAllowed is whether the account may go on with its session, and its roles.
func (h *AuthHandler) refreshAllowed(ctx context.Context, projectID string, account store.Account) (accountRoles, error) {
	roles := accountRoles{role: account.Role, allowed: account.AllowedRoles}
	switch {
	case !account.Enabled:
		return roles, refreshRefusal{status: 403, err: errAccountDisabled}
	case roles.validate() != nil:
		return roles, refreshRefusal{status: 403, err: roles.validate()}
	case account.IsGuest:
		// A guest has no address to verify; its session lives with the flag.
		return roles, h.guestRefreshAllowed(ctx, projectID)
	case !account.EmailVerified && h.settingsFor(ctx, projectID).requireEmailVerification:
		return roles, refreshRefusal{status: 403, err: errEmailNotVerified}
	}
	return roles, nil
}

// refreshRefusal is a status the account itself earns during a rotation.
type refreshRefusal struct {
	status int
	err    error
}

func (refusal refreshRefusal) Error() string { return refusal.err.Error() }

// exchangeAPIKey validates an opaque API key (esk_pub_live_… / esk_sec_live_…),
// updates last_used_at, and issues a JWT keyed to the project. The api_key flow
// does NOT issue a refresh token — the api key itself is the long-lived
// credential and clients re-exchange via grant_type=api_key when the JWT expires.
//
// Note on timing: the lookup uses the database's `=` on a VARCHAR which is not
// guaranteed constant-time. Because api keys carry ~143 bits of entropy from
// crypto/rand, brute force is infeasible regardless and the residual timing
// channel is theoretical. If this ever moves to a high-throughput hot path,
// switch to a HMAC-keyed lookup with a constant-time server-side comparison.
func (h *AuthHandler) exchangeAPIKey(r *http.Request, projectID, apiKey string) (*domain.AuthResponse, int, error) {
	if apiKey == "" {
		return nil, 400, errMissingAPIKey
	}
	db, err := h.poolMgr.GetStore(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		status, perr := poolFailure(err)
		return nil, status, perr
	}

	key, err := db.APIKeyByHash(r.Context(), service.HashAPIKey(apiKey))
	if err != nil {
		return nil, 401, errInvalidAPIKey
	}
	// A secret key owned by an end user predates operator-only key management
	// and must never yield a service token.
	if key.Type == string(service.KeyTypeSecret) && key.CreatedBy != nil {
		return nil, 401, errInvalidAPIKey
	}

	_ = db.TouchAPIKey(r.Context(), key.ID)
	keyID, keyType := key.ID, key.Type

	resp, err := h.generateAPIKeyAuthResponse(r, projectID, keyID, keyType)
	if err != nil {
		return nil, 500, errTokenGeneration
	}
	return resp, 200, nil
}

// generateAuthResponse starts a new session for a user who signed in by method.
func (h *AuthHandler) generateAuthResponse(r *http.Request, projectID string, user domain.UserInfo, roles accountRoles, emailVerified bool, method string) (*domain.AuthResponse, error) {
	return h.startSession(r, projectID, user, roles, emailVerified, h.newRefreshSession(method))
}

// startSession stores the session's first refresh token and signs its access token.
func (h *AuthHandler) startSession(r *http.Request, projectID string, user domain.UserInfo, roles accountRoles, emailVerified bool, session store.RefreshSession) (*domain.AuthResponse, error) {
	db, err := h.poolMgr.GetStore(r.Context(), chi.URLParam(r, "orgSlug"), projectID)
	if err != nil {
		return nil, err
	}
	refreshToken, err := storeRefreshToken(r.Context(), db, user.ID, session)
	if err != nil {
		return nil, err
	}
	return h.sessionResponse(r, projectID, user, roles, emailVerified, refreshToken, session)
}

// projectLabels are the display names a token carries next to projectId,
// and whether its subject is the account id (EXC-662).
type projectLabels struct {
	orgSlug       string
	projectName   string
	orgName       string
	stableSubject bool
	// mfa is whether tokens carry the session's aal and amr.
	mfa bool
}

// labelsFor looks up display names from provisioning (cached per projectId).
// Best-effort: an unreachable provisioning serves the last copy read, else
// projectId/orgSlug, so sign-in never blocks on a metadata lookup.
func (h *AuthHandler) labelsFor(r *http.Request, projectID string) projectLabels {
	labels := projectLabels{orgSlug: chi.URLParam(r, "orgSlug"), projectName: projectID}
	labels.orgName = labels.orgSlug
	info, err := h.poolMgr.GetProjectInfo(r.Context(), projectID)
	if err != nil {
		cached, ok := h.poolMgr.CachedProjectInfo(projectID)
		if !ok {
			return labels
		}
		info = cached
	}
	labels.stableSubject = info.StableSubject
	labels.mfa = info.MFAEnabled
	if info.ProjectName != "" {
		labels.projectName = info.ProjectName
	}
	if info.OrgName != "" {
		labels.orgName = info.OrgName
	}
	if info.OrgSlug != "" {
		labels.orgSlug = info.OrgSlug
	}
	return labels
}

// accountRoles is an account's users.role and users.allowed_roles (nil = [role]).
type accountRoles struct {
	role    string
	allowed []string
}

// validate refuses sign-in for an account whose roles cannot go in a token.
func (roles accountRoles) validate() error {
	_, err := auth.AccountAllowedRoles(roles.role, roles.allowed)
	return err
}

// endUserClaims builds an end-user access token whose default role is the
// account's users.role and whose allowed roles are users.allowed_roles.
func endUserClaims(projectID string, labels projectLabels, user domain.UserInfo, roles accountRoles, emailVerified bool) (auth.Claims, error) {
	allowed, err := auth.AccountAllowedRoles(roles.role, roles.allowed)
	if err != nil {
		return auth.Claims{}, err
	}
	subject := user.Email
	var isGuest *bool
	// Guests exist only while the flag is on, and have no address to name.
	if labels.stableSubject || user.IsGuest {
		subject = strconv.FormatInt(user.ID, 10)
		guest := user.IsGuest
		isGuest = &guest
	}
	return auth.Claims{
		Sub:          subject,
		Email:        user.Email,
		IsGuest:      isGuest,
		UserID:       user.ID,
		ProjectID:    projectID,
		OrgSlug:      labels.orgSlug,
		ProjectName:  labels.projectName,
		OrgName:      labels.orgName,
		Role:         roles.role,
		AllowedRoles: allowed,
		// Edge functions branch on X-Excalibase-Scope to tell signed-in users
		// from api-key traffic.
		Scope:         "authenticated",
		EmailVerified: emailVerified,
	}, nil
}

// apiKeyClaims builds an api-key token: a publishable key signs in as anon,
// a secret key as service. Neither carries a userId.
func apiKeyClaims(projectID string, labels projectLabels, keyID int64, keyType string) (auth.Claims, error) {
	var role, scope string
	switch keyType {
	case string(service.KeyTypePublishable):
		role, scope = auth.RoleAnon, "public"
	case string(service.KeyTypeSecret):
		role, scope = auth.RoleService, "service"
	default:
		return auth.Claims{}, fmt.Errorf("unknown api key type %q", keyType)
	}
	return auth.Claims{
		Sub:          fmt.Sprintf("apikey:%d", keyID),
		ProjectID:    projectID,
		OrgSlug:      labels.orgSlug,
		ProjectName:  labels.projectName,
		OrgName:      labels.orgName,
		Role:         role,
		AllowedRoles: []string{role},
		Scope:        scope,
		KeyID:        keyID,
	}, nil
}

// sessionResponse signs an end-user access token and pairs it with the
// session's refresh token; the session says when and how the user signed in.
func (h *AuthHandler) sessionResponse(r *http.Request, projectID string, user domain.UserInfo, roles accountRoles, emailVerified bool, refreshToken string, session store.RefreshSession) (*domain.AuthResponse, error) {
	labels := h.labelsFor(r, projectID)
	claims, err := endUserClaims(projectID, labels, user, roles, emailVerified)
	if err != nil {
		return nil, err
	}
	if !session.AuthTime.IsZero() {
		claims.AuthTime = session.AuthTime.Unix()
	}
	// An aal2 session exists only through MFA, so it keeps its level even
	// while the settings cannot be read.
	if labels.mfa || store.LevelOf(session.AAL) == store.AAL2 {
		claims.AAL, claims.AMR = assuranceClaims(session)
	}
	accessToken, err := h.jwtService.Sign(claims)
	if err != nil {
		return nil, err
	}
	return &domain.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(h.jwtService.TTL()),
		User:         &user,
	}, nil
}

// generateAPIKeyAuthResponse issues a JWT for an api-key grant. It does not
// create a refresh token: the api key itself is the long-lived credential.
func (h *AuthHandler) generateAPIKeyAuthResponse(r *http.Request, projectID string, keyID int64, keyType string) (*domain.AuthResponse, error) {
	claims, err := apiKeyClaims(projectID, h.labelsFor(r, projectID), keyID, keyType)
	if err != nil {
		return nil, err
	}
	accessToken, err := h.jwtService.Sign(claims)
	if err != nil {
		return nil, err
	}
	return &domain.AuthResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(h.jwtService.TTL()),
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
	case "pkce":
		resp, code, err = h.exchangePKCE(r, projectID, req.AuthCode, req.CodeVerifier)
	default:
		httpError(w, errUnsupportedGrant.Error(), 400)
		return
	}
	if err != nil {
		writeError(w, err, code)
		return
	}
	writeJSON(w, resp)
}

// writeError is httpError that also tells a busy caller when to come back.
func writeError(w http.ResponseWriter, err error, code int) {
	if errors.Is(err, errHashingBusy) {
		w.Header().Set("Retry-After", "1")
	}
	httpError(w, err.Error(), code)
}

// writeHashFailure answers a hash that could not run: saturation and a
// cancelled request are capacity, anything else is ours.
func writeHashFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, auth.ErrHashBusy) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		writeError(w, errHashingBusy, 503)
		return
	}
	httpError(w, "internal error", 500)
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

// safeLog strips CR/LF/TAB from a string so user-controlled values can't inject
// fake log lines (CWE-117 log injection). Apply to any string sourced from a
// request header, path param, or body before passing to log.Printf.
var logSanitizer = strings.NewReplacer("\r", "_", "\n", "_", "\t", "_")

func safeLog(s string) string {
	return logSanitizer.Replace(s)
}

// poolFailure is the status and message for a project database that could not
// be reached. A project created without a database (EXC-426) is its state,
// 409, and not the outage every other failure is.
func poolFailure(err error) (int, error) {
	if errors.Is(err, pool.ErrNoDatabase) {
		return http.StatusConflict, errProjectHasNoDatabase
	}
	return http.StatusServiceUnavailable, errProjectDBUnavailable
}

func writePoolFailure(w http.ResponseWriter, err error) {
	status, message := poolFailure(err)
	httpError(w, message.Error(), status)
}
