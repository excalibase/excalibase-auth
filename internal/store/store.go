// Package store is the per-project end-user database behind excalibase-auth.
// One Store serves one project: a Postgres project's auth schema or a MySQL
// project's auth database (ADR 0041). Both engines keep the same behaviour;
// every query is parameterised and every table name is a literal.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/excalibase/auth/internal/domain"
	"github.com/google/uuid"
)

// ErrNotFound means no row matched: an unknown account, a token that is not
// live, a missing key.
var ErrNotFound = errors.New("not found")

// ErrUnavailable means a transaction could not be started: the database is
// not answering.
var ErrUnavailable = errors.New("project database unavailable")

// ErrNoAccount means a live refresh token's account could not be read.
var ErrNoAccount = errors.New("refresh token has no account")

// TokenKind names one of the single-use link tables.
type TokenKind int

const (
	EmailVerification TokenKind = iota + 1
	PasswordReset
)

// Account is an end user's row as sign-in reads it.
type Account struct {
	ID            int64
	Email         string
	PasswordHash  string
	FullName      string
	Role          string
	AllowedRoles  []string // nil means only Role
	Enabled       bool
	EmailVerified bool
}

// RefreshSession is one login: every token rotated from it shares the family
// and the expiry.
type RefreshSession struct {
	FamilyID uuid.UUID
	Expiry   time.Time
}

// RefreshState is what a presented refresh token's row says about it.
type RefreshState struct {
	Revoked  bool
	FamilyID uuid.UUID
}

// SingleUseToken is a live link row found by its hash.
type SingleUseToken struct {
	RowID            int64
	UserID           int64
	Hash             string
	ConfirmsPassword bool
}

// APIKey is a live key found by its hash.
type APIKey struct {
	ID        int64
	Type      string
	CreatedBy *int64
}

// APIKeyListing is one row of the key listing; neither hash nor plaintext.
type APIKeyListing struct {
	ID         int64
	Prefix     string
	Type       string
	Name       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// RoleChange is one validated change of an account's roles; Stored is what
// allowed_roles receives (nil when the caller gave no list), Allowed its reading.
type RoleChange struct {
	UserID  int64
	Role    string
	Allowed []string
	Stored  []string
	Actor   string
}

// Store is one project's end-user database.
type Store interface {
	// InsertUser creates an account with role 'user' unless the address is
	// taken; created reports which.
	InsertUser(ctx context.Context, email, passwordHash, fullName string) (id int64, created bool, err error)
	// ReplaceUnverified sets a new password and name on an unverified account.
	ReplaceUnverified(ctx context.Context, email, passwordHash, fullName string) (int64, error)
	AccountByEmail(ctx context.Context, email string) (Account, error)
	TouchLastLogin(ctx context.Context, userID int64) error
	SetPassword(ctx context.Context, userID int64, passwordHash string) error
	// MarkVerified records the proof, revokes every refresh token and, unless
	// keepPassword, replaces the password with replacement, all at once.
	MarkVerified(ctx context.Context, userID int64, keepPassword bool, replacement string) (email string, err error)
	ListUsers(ctx context.Context, limit, offset int) ([]domain.ManagedUser, error)
	// ApplyRoleChange updates the account, revokes its refresh tokens and
	// writes the audit row in one transaction.
	ApplyRoleChange(ctx context.Context, change RoleChange) (domain.ManagedUser, error)

	InsertRefreshToken(ctx context.Context, hash string, userID int64, session RefreshSession) error
	// RotateRefreshToken consumes a live token and stores its successor in one
	// transaction; of concurrent rotations exactly one succeeds. accept sees
	// the account first; its error rolls everything back. ErrNotFound means
	// the token is unknown, expired or already used.
	RotateRefreshToken(ctx context.Context, presented, successor string, accept func(Account) error) (Account, RefreshSession, error)
	RefreshTokenState(ctx context.Context, hash string) (RefreshState, error)
	RevokeRefreshFamily(ctx context.Context, familyID uuid.UUID) error
	RevokeRefreshToken(ctx context.Context, hash string) error
	RevokeUserRefreshTokens(ctx context.Context, userID int64) error

	// IssueToken consumes every outstanding link of the kind for the user and
	// stores the new one. confirmsPassword applies to email verification only.
	IssueToken(ctx context.Context, kind TokenKind, userID int64, hash string, expiresAt time.Time, confirmsPassword bool) error
	LookupToken(ctx context.Context, kind TokenKind, hash string) (SingleUseToken, error)
	// ClaimToken consumes a looked-up row; false when another request did.
	ClaimToken(ctx context.Context, kind TokenKind, rowID int64) (bool, error)

	CreateAPIKey(ctx context.Context, hash, prefix, keyType, name string) (int64, time.Time, error)
	ListAPIKeys(ctx context.Context) ([]APIKeyListing, error)
	// RevokeAPIKey reports whether a live key was revoked.
	RevokeAPIKey(ctx context.Context, id int64) (bool, error)
	APIKeyByHash(ctx context.Context, hash string) (APIKey, error)
	TouchAPIKey(ctx context.Context, id int64) error

	Close()
}
