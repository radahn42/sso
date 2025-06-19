package models

type RefreshToken struct {
	ID        int64
	UserID    int64
	AppID     int
	Token     string
	ExpiresAt int64
	CreatedAt int64
}
