// Package store is the per-project end-user database behind excalibase-auth.
// One Store serves one project: a Postgres project's auth schema or a MySQL
// project's auth database (ADR 0041). Both engines keep the same behaviour;
// every query is parameterised and every table name is a literal.
package store

import (
	"context"
	"errors"
	"strings"
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

// ErrSignupsDisabled means the project takes no new accounts.
var ErrSignupsDisabled = errors.New("new sign-ups are disabled")

// ErrAmbiguousEmail means accounts differing only in the case of their
// address match a provider sign-in and none matches it exactly.
var ErrAmbiguousEmail = errors.New("more than one account matches the address")

// ErrAccountDisabled means the account an address reaches is switched off;
// no sign-in may reach it, nor replace it.
var ErrAccountDisabled = errors.New("account is disabled")

// ErrRateLimited means a send would pass the address's or the project's budget.
var ErrRateLimited = errors.New("too many codes sent")

// ErrIdentityExists means the identity, or the address, already belongs to an account.
var ErrIdentityExists = errors.New("identity already exists")

// ErrAddressUnproven means the account's own address was never proven, so
// nothing may be linked to it.
var ErrAddressUnproven = errors.New("account address is not proven")

// ErrLastSignInMethod means an unlink would leave the account no way to sign in.
var ErrLastSignInMethod = errors.New("last sign-in method")

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
	// IsGuest marks an account made with no address; it has the guest role
	// until it proves an address or links a provider.
	IsGuest bool
}

// RefreshSession is one login: every token rotated from it shares the family
// and the expiry.
type RefreshSession struct {
	FamilyID uuid.UUID
	Expiry   time.Time
	// AuthTime is when the owner signed in; zero for sessions older than it.
	AuthTime time.Time
}

// RefreshState is what a presented refresh token's row says about it.
type RefreshState struct {
	Revoked  bool
	FamilyID uuid.UUID
	UserID   int64
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

// EmailProvider names an address linked to an account; its subject is the
// address's AddressKey.
const EmailProvider = "email"

// HasUsablePassword is whether a stored hash can match a password; a hash
// replaced by a marker starting with "!" cannot.
func HasUsablePassword(hash string) bool {
	return hash != "" && !strings.HasPrefix(hash, "!")
}

// AddressKey is an address as a linked identity keeps it: only ASCII letters
// are lowered, so Go, Postgres and MySQL agree on it.
func AddressKey(address string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, address)
}

// IdentityClaim is a provider account whose email address the provider verified.
type IdentityClaim struct {
	Provider string
	Subject  string
	Email    string
	FullName string
}

// Identity is one way an account signs in besides its own address.
type Identity struct {
	ID           int64
	Provider     string
	Email        string
	CreatedAt    time.Time
	LastSignInAt *time.Time
}

// AddressMatch is an account whose address equals a provider's, ignoring case.
type AddressMatch struct {
	ID       int64
	Exact    bool
	Verified bool
	Enabled  bool
}

// PickAddressMatch takes the exact match, else the only one; matches come
// exact first. none is the engine's no-rows error.
func PickAddressMatch(matches []AddressMatch, none error) (AddressMatch, error) {
	switch {
	case len(matches) == 0:
		return AddressMatch{}, none
	case matches[0].Exact || len(matches) == 1:
		return matches[0], nil
	default:
		return AddressMatch{}, ErrAmbiguousEmail
	}
}

// IdentityOutcome says how a provider sign-in reached its account.
type IdentityOutcome int

const (
	// IdentityKnown is a provider account that signed in before.
	IdentityKnown IdentityOutcome = iota + 1
	// IdentityLinked joined a verified account with the same address.
	IdentityLinked
	// IdentityTookOver claimed an unverified account with the same address:
	// its password was cleared and its sessions and links ended.
	IdentityTookOver
	// IdentityCreated is a new account.
	IdentityCreated
)

// FlowState is a provider sign-in between /authorize and the callback.
type FlowState struct {
	StateHash           string
	Provider            string
	IDPCodeVerifier     string
	Nonce               string
	ClientCodeChallenge string
	RedirectTo          string
	// LinkUserID is the signed-in account a linking flow adds the identity to.
	LinkUserID int64
	ExpiresAt  time.Time
}

// AuthCode is the single-use code a sign-in hands back to the app, redeemed
// with the PKCE verifier whose challenge it carries.
type AuthCode struct {
	CodeHash      string
	UserID        int64
	CodeChallenge string
	// Link is the identity the redemption links to UserID; empty for a sign-in.
	Link      IdentityClaim
	ExpiresAt time.Time
}

// Kinds of emailed sign-in secret.
const (
	OTPMagicLink = "magiclink"
	OTPEmailCode = "email"
)

// EmailOTP is one emailed sign-in: a link, stored as its SHA-256, or a code,
// stored as an HMAC. Either is spent once, with the PKCE verifier whose
// challenge it carries.
type EmailOTP struct {
	Email         string
	Kind          string
	LinkHash      string
	CodeHMAC      string
	CodeChallenge string
	CreateUser    bool
	// Mailed says whether the send goes out; an address that reaches no
	// account is still recorded so the budgets cannot tell the two apart.
	Mailed    bool
	IP        string
	Attempts  int
	ExpiresAt time.Time
	// LinkUserID is the signed-in account the address is linked to once proven.
	LinkUserID int64
}

// OTPLimits are the send budgets, counted from the rows themselves so every
// replica shares them.
type OTPLimits struct {
	MinInterval    time.Duration
	PerAddressHour int
	PerProjectDay  int // mailed sends only
	PerIPDay       int
	// LinksPerAccountDay bounds the address links one account asks for.
	LinksPerAccountDay int
}

// OTPAttempts bound the guesses at one code; the send budgets bound how many
// codes there are to guess at.
type OTPAttempts struct {
	PerCode int
}

// OTPLookup finds a link by its hash, or else the address's live code sent
// with the challenge, so guesses from another browser cannot spend it.
type OTPLookup struct {
	LinkHash      string
	Email         string
	CodeChallenge string
}

// LinkResult is what a link changed besides adding the identity.
type LinkResult struct {
	// Deleted are the unproven accounts that answered to the linked address.
	Deleted []int64
	// Upgraded is true when the account was a guest and is now a full account.
	Upgraded bool
}

// GuestRole is the role a guest account starts with; it has no grants
// until the project gives it some.
const GuestRole = "guest"

// GuestLimits bound guest sign-ups, counted from rows every replica shares.
type GuestLimits struct {
	PerClientHour int
	PerProjectDay int
}

// AuditEvent is one row of the project's sign-in trail.
type AuditEvent struct {
	UserID int64 // zero when no account is known
	Event  string
	Method string
	IP     string
}

// Store is one project's end-user database.
type Store interface {
	// InsertUser creates an account with role 'user' unless the address is
	// taken; created reports which.
	InsertUser(ctx context.Context, email, passwordHash, fullName string) (id int64, created bool, err error)
	// ReplaceUnverified sets a new password and name on an unverified account.
	ReplaceUnverified(ctx context.Context, email, passwordHash, fullName string) (int64, error)
	AccountByEmail(ctx context.Context, email string) (Account, error)
	AccountByID(ctx context.Context, id int64) (Account, error)
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

	// SignInWithIdentity finds or creates the account of a provider account in
	// one transaction. ErrSignupsDisabled when it would create one and
	// allowCreate is false.
	SignInWithIdentity(ctx context.Context, claim IdentityClaim, allowCreate bool) (Account, IdentityOutcome, error)
	// SaveFlowState stores a sign-in in flight and drops expired ones.
	SaveFlowState(ctx context.Context, state FlowState) error
	// ConsumeFlowState returns and deletes a live state; ErrNotFound otherwise.
	ConsumeFlowState(ctx context.Context, stateHash string) (FlowState, error)
	// SaveAuthCode stores a code and drops expired ones.
	SaveAuthCode(ctx context.Context, code AuthCode) error
	// RedeemAuthCode spends a live code once; ErrNotFound otherwise.
	RedeemAuthCode(ctx context.Context, codeHash string) (AuthCode, error)

	// SaveEmailOTP records a send within the limits, ends the address's earlier
	// live links and codes sent with the same challenge, and drops rows older
	// than a day. ErrRateLimited past an address or IP budget; past the
	// project's daily budget the row is kept and reported as not mailed.
	SaveEmailOTP(ctx context.Context, otp EmailOTP, limits OTPLimits) (bool, error)
	// RedeemEmailOTP spends the live row the lookup finds when check accepts
	// it. A refusal counts an attempt and spends a link, or a code at its last
	// attempt; a code is not offered once its address used up the day's
	// guesses. ErrNotFound for no row and for a refusal alike.
	RedeemEmailOTP(ctx context.Context, lookup OTPLookup, attempts OTPAttempts, check func(EmailOTP) bool) (EmailOTP, error)
	// SignInWithEmail finds or creates the account of an address its owner
	// just proved, by the rule a provider sign-in follows.
	SignInWithEmail(ctx context.Context, email, fullName string, allowCreate bool) (Account, IdentityOutcome, error)
	// AccountByAddress is the account an address reaches, whatever its case.
	AccountByAddress(ctx context.Context, email string) (Account, error)
	RecordAudit(ctx context.Context, event AuditEvent) error

	// LinkableAccount is nil for an enabled account whose own address is
	// proven: ErrAccountDisabled, ErrAddressUnproven or ErrNotFound otherwise.
	LinkableAccount(ctx context.Context, userID int64) error
	// LinkIdentity adds an identity to a linkable account. ErrIdentityExists
	// when any account holds the identity, or, for an address, when another
	// proven account answers to it; the unproven ones answering to it are
	// deleted and their ids returned.
	// A guest is upgraded by the link: it takes the identity's address,
	// proven, and leaves the guest role.
	LinkIdentity(ctx context.Context, userID int64, claim IdentityClaim) (LinkResult, error)
	ListIdentities(ctx context.Context, userID int64) ([]Identity, error)
	// UnlinkIdentity removes one of the account's identities unless no other
	// identity nor a password would be left: ErrLastSignInMethod.
	UnlinkIdentity(ctx context.Context, userID, identityID int64) (Identity, error)

	// Profile reads an account with its metadata.
	Profile(ctx context.Context, userID int64) (Profile, error)
	// UpdateProfile applies a change in one transaction; ErrMetadataTooLarge
	// when a merged object would pass the limit.
	UpdateProfile(ctx context.Context, userID int64, change ProfileChange) (Profile, error)
	// ChangePassword stores the hash, ends every session and link in flight and
	// every unspent reset link, all at once.
	ChangePassword(ctx context.Context, userID int64, passwordHash string) error
	// SaveEmailChange records a request within the limits and ends the
	// account's earlier ones. Past the project's daily budget nothing is
	// mailed; the link is not mailed when the address answers to another
	// proven or disabled account. ErrRateLimited past the account's budget;
	// ErrAccountDisabled, ErrAddressUnproven or ErrNotFound for the account.
	SaveEmailChange(ctx context.Context, change EmailChange, limits EmailChangeLimits) (EmailChangeMail, error)
	// ConfirmEmailChange spends the account's live request and moves it to
	// its address, proven, deleting the unproven accounts answering to it and
	// ending every unspent link sent to the old one. ErrNotFound unless the
	// request is the account's; ErrIdentityExists when another proven or
	// disabled account holds the address; ErrUserReferenced when an app table
	// references an unproven one.
	ConfirmEmailChange(ctx context.Context, userID int64, tokenHash string) (ChangedEmail, error)
	// RevokeOtherSessions ends every session of the account but keep.
	RevokeOtherSessions(ctx context.Context, userID int64, keep uuid.UUID) error
	// DeleteUser removes the account and everything of it in the auth tables;
	// ErrUserReferenced when an app table still references it.
	DeleteUser(ctx context.Context, userID int64) error

	// CreateGuest makes an account with no address, no password and the guest
	// role, counting the sign-up against the client's and the project's
	// budgets: ErrRateLimited past either, and then nothing is written.
	CreateGuest(ctx context.Context, client string, limits GuestLimits) (Account, error)
	// ClaimGuestCleanup is true for one caller per interval across replicas.
	ClaimGuestCleanup(ctx context.Context, every time.Duration) (bool, error)
	// DeleteInactiveGuests removes up to max guests with no sign-in nor
	// refresh since cutoff; one an app table references is skipped.
	DeleteInactiveGuests(ctx context.Context, cutoff time.Time, max int) (int, error)

	CreateAPIKey(ctx context.Context, hash, prefix, keyType, name string) (int64, time.Time, error)
	ListAPIKeys(ctx context.Context) ([]APIKeyListing, error)
	// RevokeAPIKey reports whether a live key was revoked.
	RevokeAPIKey(ctx context.Context, id int64) (bool, error)
	APIKeyByHash(ctx context.Context, hash string) (APIKey, error)
	TouchAPIKey(ctx context.Context, id int64) error

	Close()
}
