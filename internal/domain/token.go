package domain

import "time"

type RefreshToken struct {
	ID         int64
	Token      string
	UserID     int64
	ExpiryDate time.Time
	CreatedAt  time.Time
	Revoked    bool
}
