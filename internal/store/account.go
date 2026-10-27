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
	// GuestClient is set for a guest's request: its client (IP or IPv6 /64),
	// counted against the guest budgets below.
	GuestClient string
}

// EmailChangeLimits are the change budgets, counted from the rows so every
// replica shares them.
type EmailChangeLimits struct {
	MinInterval   time.Duration
	PerAccountDay int
	PerProjectDay int // mailed requests only
	// A guest is free to make, so its requests are also capped per client
	// and held to a share of the project's budget, leaving the rest to full accounts.
	PerGuestClientDay  int
	GuestPerProjectDay int
}

// EmailChangeMail says which mails a recorded change may send: the notice to
// the current address, and the link only when the new address is free.
type EmailChangeMail struct {
	Notice bool
	Link   bool
}

// ChangedEmail is an address change that was confirmed.
type ChangedEmail struct {
	UserID   int64
	OldEmail string
	NewEmail string
	// Replaced are the unproven accounts that answered to the new address.
	Replaced []int64
}
