package domain

import "time"

type User struct {
	ID          int64
	Email       string
	Password    string // bcrypt hash
	FullName    string
	Role        string
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
	LastLoginAt *time.Time
}
