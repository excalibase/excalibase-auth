package store

import (
	"errors"
	"slices"
	"strings"
	"time"
)

// Factor statuses: a factor counts for aal2 only once a code proved it.
const (
	FactorUnverified = "unverified"
	FactorVerified   = "verified"
)

// FactorTOTP is the only factor type so far.
const FactorTOTP = "totp"

// Assurance levels a session can hold.
const (
	AAL1 = 1
	AAL2 = 2
)

var (
	// ErrTooManyFactors means the account holds as many factors as it may.
	ErrTooManyFactors = errors.New("too many factors")
	// ErrFactorNameTaken means the account has a factor with that name.
	ErrFactorNameTaken = errors.New("factor name taken")
	// ErrInvalidChallenge means the challenge is unknown, spent, expired or another factor's.
	ErrInvalidChallenge = errors.New("invalid challenge")
	// ErrInvalidCode means the code did not match; the failure was counted.
	ErrInvalidCode = errors.New("invalid code")
	// ErrTooManyAttempts means the failure budget is spent; nothing was checked.
	ErrTooManyAttempts = errors.New("too many attempts")
	// ErrInsufficientAAL means an unverified factor of an account that already
	// has a verified one was answered from an aal1 session.
	ErrInsufficientAAL = errors.New("insufficient assurance level")
)

// Factor is a second factor as its owner sees it.
type Factor struct {
	ID           string
	UserID       int64
	FactorType   string
	FriendlyName string
	Status       string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// NewFactor is a factor about to be stored, its secret already sealed.
type NewFactor struct {
	ID           string
	UserID       int64
	FriendlyName string
	SecretSealed []byte
}

// FactorSecret is what a code check needs: the sealed secret and the newest
// step already spent.
type FactorSecret struct {
	Factor
	SecretSealed []byte
	LastUsedStep int64
}

// FactorAttempt is one code typed for a factor's challenge.
type FactorAttempt struct {
	UserID      int64
	FactorID    string
	ChallengeID string
	// CallerAAL2 is whether the session answering passed a second factor already.
	CallerAAL2 bool
}

// FactorCheck reports the step a code matched, or false; an error (the secret
// could not be read) aborts the attempt without counting it.
type FactorCheck func(FactorSecret) (step int64, ok bool, err error)

// MFALimits bound factors and wrong codes, counted from rows every replica shares.
type MFALimits struct {
	MaxFactors int
	// MaxFailures wrong codes within FailureWindow lock a factor, or the
	// account's recovery codes, until the oldest ages out.
	MaxFailures   int
	FailureWindow time.Duration
	// MaxDailyFailures caps wrong codes across all of an account's factors
	// and recovery codes in a day, so more factors give no more guesses.
	MaxDailyFailures int
	// StaleUnverified is how long an unverified factor is kept.
	StaleUnverified time.Duration
}

// VerifiedFactor is the outcome of a code that matched.
type VerifiedFactor struct {
	Factor Factor
	// FirstForAccount is true when no other factor of the account was verified:
	// the account just turned MFA on and gets its recovery codes.
	FirstForAccount bool
}

// FactorListing is an account's factors and how many recovery codes are unspent.
type FactorListing struct {
	Factors                []Factor
	RecoveryCodesRemaining int
}

// JoinAMR is the column form of a method list.
func JoinAMR(methods []string) string {
	return strings.Join(methods, ",")
}

// SplitAMR reads the column back; empty is no methods.
func SplitAMR(column string) []string {
	if column == "" {
		return nil
	}
	return strings.Split(column, ",")
}

// LevelOf is a stored level, where zero is a session older than the column.
func LevelOf(aal int) int {
	if aal == AAL2 {
		return AAL2
	}
	return AAL1
}

// WithMethod is methods plus method, unless it is already there.
func WithMethod(methods []string, method string) []string {
	if slices.Contains(methods, method) {
		return methods
	}
	return append(append([]string(nil), methods...), method)
}
