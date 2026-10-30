package handler

import (
	"github.com/excalibase/auth/internal/auth"
	"github.com/excalibase/auth/internal/store"
)

// Methods a session's amr names, first factor first.
const (
	methodPassword  = "password"
	methodOAuth     = "oauth"
	methodGuest     = "guest"
	methodMagicLink = "magiclink"
	methodEmailCode = "email_otp"
	methodTOTP      = "totp"
	methodRecovery  = "recovery"
)

// Token values of the aal claim.
const (
	claimAAL1 = "aal1"
	claimAAL2 = "aal2"
)

// otpMethod names an emailed sign-in by its kind.
func otpMethod(kind string) string {
	if kind == store.OTPMagicLink {
		return methodMagicLink
	}
	return methodEmailCode
}

// assuranceClaims are a session's aal and amr as the token carries them.
func assuranceClaims(session store.RefreshSession) (string, []string) {
	if store.LevelOf(session.AAL) == store.AAL2 {
		return claimAAL2, session.AMR
	}
	return claimAAL1, session.AMR
}

// carriedSession keeps the caller's own level and methods in a session that
// replaces theirs, as a password change does; the claims are ours, signed.
func carriedSession(session store.RefreshSession, caller *auth.Claims) store.RefreshSession {
	if caller == nil || caller.AAL == "" {
		return session
	}
	if caller.AAL == claimAAL2 {
		session.AAL = store.AAL2
	}
	if len(caller.AMR) > 0 {
		session.AMR = append([]string(nil), caller.AMR...)
	}
	return session
}
