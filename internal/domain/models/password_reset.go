package models

import "time"

type PasswordResetToken struct {
	Token     string
	UserID    int64
	ExpiresAt time.Time
}
