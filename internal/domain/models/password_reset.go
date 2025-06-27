package models

type PasswordResetToken struct {
	Token     string
	UserID    int64
	ExpiresAt int64
}
