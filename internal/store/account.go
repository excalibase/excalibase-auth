package store

import (
	"encoding/json"
	"errors"
	"time"
)

// ErrUserReferenced means an app table still references the account.
var ErrUserReferenced = errors.New("account is still referenced")

// Profile is an account as its owner and the project's admins read it.
type Profile struct {
	Account
	UserMetadata json.RawMessage
	AppMetadata  json.RawMessage
	CreatedAt    time.Time
	LastLoginAt  *time.Time
}

// ProfileChange is one update of an account's name and metadata; nil leaves
// a part as it is, a metadata patch merges into what is stored.
type ProfileChange struct {
	FullName     *string
	UserMetadata map[string]json.RawMessage
	AppMetadata  map[string]json.RawMessage
}

// EmailChange is a requested change of address, proven by the link mailed to it.
type EmailChange struct {
	UserID    int64
	NewEmail  string
	TokenHash string
	ExpiresAt time.Time
}

// EmailChangeLimits are the change budgets, counted from the rows so every
// replica shares them.
type EmailChangeLimits struct {
	MinInterval   time.Duration
	PerAccountDay int
	PerProjectDay int // mailed requests only
}

// ChangedEmail is an address change that was confirmed.
type ChangedEmail struct {
	UserID   int64
	OldEmail string
	NewEmail string
	// Replaced are the unproven accounts that answered to the new address.
	Replaced []int64
}
