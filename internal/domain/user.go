package domain

import "time"

type User struct {
	ID       int64
	Email    string
	Password string // bcrypt hash
	FullName string
	Role     string
	Enabled  bool
	// EmailVerified records that the address was proved by clicking a link.
	EmailVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
	LastLoginAt   *time.Time
}
