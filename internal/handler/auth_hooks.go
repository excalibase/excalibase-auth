package handler

import (
	"context"
	"errors"
	"log"

	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/email"
	"github.com/excalibase/auth/internal/hooks"
	"github.com/excalibase/auth/internal/pool"
	"github.com/excalibase/auth/internal/store"
)

// Auth hooks (EXC-662): the project's own HTTPS endpoints, called while the
// control plane's authhooks flag is on and the project switched them on.
const (
	codeHookFailed   = "auth_hook_failed"
	codeSignupDenied = "signup_denied"

	hookCustomAccessToken = "custom_access_token"
	hookBeforeUserCreated = "before_user_created"
	hookSendEmail         = "send_email"

	// methodGuestUpgrade asks before_user_created about a guest taking an address.
	methodGuestUpgrade = "guest_upgrade"

	decisionAllow = "allow"
	decisionDeny  = "deny"
)

var (
	errHookFailed   = errors.New(codeHookFailed)
	errSignupDenied = errors.New(codeSignupDenied)
)

// hookCaller sends one signed hook call; *hooks.Client in production.
type hookCaller interface {
	Call(ctx context.Context, target, secret string, payload, out any) error
}

// WithHooks sets the client hook calls go through; without one a project
// with hooks on fails closed.
func (h *AuthHandler) WithHooks(client hookCaller) *AuthHandler {
	h.hookClient = client
	return h
}

// hookSettings is the project's hooks, read no older than signInMaxAge.
// Unreadable settings fail closed when the last copy had hooks, so a control
// plane with the flag off behaves as before.
func (h *AuthHandler) hookSettings(ctx context.Context, projectID string) (pool.AuthHooks, error) {
	info, err := h.signInSettings(ctx, projectID)
	if err != nil {
		// With no copy at all the project's database and the relay are out of
		// reach too (both come from the control plane), so nothing proceeds unchecked.
		if cached, ok := h.poolMgr.CachedProjectInfo(projectID); ok && cached.AuthHooks != nil {
			return pool.AuthHooks{}, errHookFailed
		}
		return pool.AuthHooks{}, nil
	}
	if info.AuthHooks == nil {
		return pool.AuthHooks{}, nil
	}
	return *info.AuthHooks, nil
}

// callHook signs and sends one call; every failure is logged, audited and errHookFailed.
func (h *AuthHandler) callHook(ctx context.Context, projectID, hook, target string, userID int64, payload, out any) error {
	if h.hookClient == nil {
		return h.hookFailure(ctx, projectID, hook, userID, "no hook client")
	}
	secret, err := h.poolMgr.HookSecret(ctx, projectID)
	if err != nil {
		return h.hookFailure(ctx, projectID, hook, userID, "the signing secret is unreadable")
	}
	if err := h.hookClient.Call(ctx, target, secret, payload, out); err != nil {
		return h.hookFailure(ctx, projectID, hook, userID, failureReason(err))
	}
	return nil
}

func failureReason(err error) string {
	var failure *hooks.Failure
	if errors.As(err, &failure) {
		return failure.Reason
	}
	return "the call failed"
}

// hookFailure logs the hook and a reason, never the URL, payload or answer.
func (h *AuthHandler) hookFailure(ctx context.Context, projectID, hook string, userID int64, reason string) error {
	log.Printf("auth.hook.failed project=%s hook=%s reason=%q", safeLog(projectID), hook, safeLog(reason))
	if db, ok := h.poolMgr.OpenStores()[projectID]; ok {
		h.recordAudit(context.WithoutCancel(ctx), db, projectID, store.AuditEvent{UserID: userID, Event: "hook_failed", Method: hook})
	}
	return errHookFailed
}

type accessTokenHookRequest struct {
	Type      string         `json:"type"`
	ProjectID string         `json:"projectId"`
	UserID    int64          `json:"userId"`
	Claims    map[string]any `json:"claims"`
}

type accessTokenHookAnswer struct {
	Claims map[string]any `json:"claims"`
}

// withAccessHook lets the project's custom_access_token hook add claims and
// pick the default role; anything else it tries fails the token.
func (h *AuthHandler) withAccessHook(ctx context.Context, projectID string, claims auth.Claims) (auth.Claims, error) {
	settings, err := h.hookSettings(ctx, projectID)
	if err != nil {
		return claims, h.hookFailure(ctx, projectID, hookCustomAccessToken, claims.UserID, "the hook settings are unreadable")
	}
	if settings.CustomAccessToken == "" {
		return claims, nil
	}
	sent := h.jwtService.PublicClaims(claims)
	var answer accessTokenHookAnswer
	request := accessTokenHookRequest{Type: hookCustomAccessToken, ProjectID: projectID, UserID: claims.UserID, Claims: sent}
	if err := h.callHook(ctx, projectID, hookCustomAccessToken, settings.CustomAccessToken, claims.UserID, request, &answer); err != nil {
		return claims, err
	}
	if answer.Claims == nil {
		return claims, h.hookFailure(ctx, projectID, hookCustomAccessToken, claims.UserID, "the answer has no claims")
	}
	applied, err := hooks.ApplyAccessClaims(sent, answer.Claims, claims.AllowedRoles)
	if err != nil {
		return claims, h.hookFailure(ctx, projectID, hookCustomAccessToken, claims.UserID, failureReason(err))
	}
	claims.Role, claims.Custom = applied.Role, applied.Custom
	return claims, nil
}

// newUser is who before_user_created is asked about.
type newUser struct {
	Method   string `json:"-"`
	Provider string `json:"-"`
	Email    string `json:"email"`
	IsGuest  bool   `json:"isGuest"`
}

type userCreatedHookRequest struct {
	Type      string  `json:"type"`
	ProjectID string  `json:"projectId"`
	Method    string  `json:"method"`
	Provider  string  `json:"provider,omitempty"`
	User      newUser `json:"user"`
}

type userCreatedHookAnswer struct {
	Decision string `json:"decision"`
}

// allowNewUser asks the project's before_user_created hook: nil to go on,
// errSignupDenied for its no, errHookFailed when it cannot answer.
func (h *AuthHandler) allowNewUser(ctx context.Context, projectID string, user newUser) error {
	settings, err := h.hookSettings(ctx, projectID)
	if err != nil {
		return h.hookFailure(ctx, projectID, hookBeforeUserCreated, 0, "the hook settings are unreadable")
	}
	if settings.BeforeUserCreated == "" {
		return nil
	}
	request := userCreatedHookRequest{Type: hookBeforeUserCreated, ProjectID: projectID, Method: user.Method, Provider: user.Provider, User: user}
	var answer userCreatedHookAnswer
	if err := h.callHook(ctx, projectID, hookBeforeUserCreated, settings.BeforeUserCreated, 0, request, &answer); err != nil {
		return err
	}
	switch answer.Decision {
	case decisionAllow:
		return nil
	case decisionDeny:
		return errSignupDenied
	}
	return h.hookFailure(ctx, projectID, hookBeforeUserCreated, 0, "the decision is neither allow nor deny")
}

type sendEmailHookRequest struct {
	Type      string        `json:"type"`
	ProjectID string        `json:"projectId"`
	Email     hookEmailBody `json:"email"`
}

type hookEmailBody struct {
	To       string            `json:"to"`
	Template string            `json:"template"`
	Data     map[string]string `json:"data"`
}

// sendMail delivers through the project's send_email hook while it is on,
// never falling back to the relay (a failure is logged and audited by
// callHook), and through the relay otherwise.
func (h *AuthHandler) sendMail(ctx context.Context, msg email.Message) error {
	settings, err := h.hookSettings(ctx, msg.ProjectID)
	if err != nil {
		return h.hookFailure(ctx, msg.ProjectID, hookSendEmail, 0, "the hook settings are unreadable")
	}
	if settings.SendEmail == "" {
		return h.emailSender.Send(ctx, msg)
	}
	request := sendEmailHookRequest{Type: hookSendEmail, ProjectID: msg.ProjectID,
		Email: hookEmailBody{To: msg.To, Template: msg.Template, Data: msg.Data}}
	// After the answer, so the hook's latency tells nothing about the address.
	detached := context.WithoutCancel(ctx)
	h.dispatchMail(func() {
		callCtx, cancel := context.WithTimeout(detached, otpMailTimeout)
		defer cancel()
		_ = h.callHook(callCtx, msg.ProjectID, hookSendEmail, settings.SendEmail, 0, request, nil)
	})
	return nil
}

// hookRefusalCode is the error code a provider callback redirects with.
func hookRefusalCode(err error) string {
	if errors.Is(err, errSignupDenied) {
		return codeSignupDenied
	}
	return codeHookFailed
}

// guestUpgradeAllowed asks before_user_created before a guest takes an
// address or a provider, so guests cannot route around the sign-up policy.
func (h *AuthHandler) guestUpgradeAllowed(ctx context.Context, db store.Store, projectID string, userID int64, provider, address string) error {
	settings, err := h.hookSettings(ctx, projectID)
	if err != nil {
		return h.hookFailure(ctx, projectID, hookBeforeUserCreated, userID, "the hook settings are unreadable")
	}
	if settings.BeforeUserCreated == "" {
		return nil
	}
	account, err := db.AccountByID(ctx, userID)
	if err != nil || !account.IsGuest {
		return nil
	}
	return h.allowNewUser(ctx, projectID, newUser{Method: methodGuestUpgrade, Provider: provider, Email: address})
}
