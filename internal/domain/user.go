package domain

import "time"

type User struct {
	ID       int64
	Email    string
	Password string // bcrypt hash
	FullName string
	Role     string
	// AllowedRoles is users.allowed_roles; nil means only Role.
	AllowedRoles []string
	Enabled      bool
	// EmailVerified records that the address was proved by clicking a link.
	EmailVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
	LastLoginAt   *time.Time
}

// ManagedUser is an account as the project's user administration sees it.
type ManagedUser struct {
	ID            int64    `json:"id"`
	Email         string   `json:"email"`
	Role          string   `json:"role"`
	AllowedRoles  []string `json:"allowedRoles"`
	Enabled       bool     `json:"enabled"`
	EmailVerified bool     `json:"emailVerified"`
}

// SetRoleRequest is the body of PUT /users/{userId}/role. A nil AllowedRoles
// means the account may act only as Role.
type SetRoleRequest struct {
	Role         string   `json:"role"`
	AllowedRoles []string `json:"allowedRoles"`
}
