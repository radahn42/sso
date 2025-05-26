package models

type ValidatedTokenInfo struct {
	UserID      int64
	Email       string
	AppID       int
	Roles       []string
	Permissions []string
	ExpiresAt   int64
}
