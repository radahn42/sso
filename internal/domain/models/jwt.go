package models

import "github.com/golang-jwt/jwt/v5"

type UserClaims struct {
	jwt.RegisteredClaims
	UserID int64    `json:"user_id"`
	Email  string   `json:"email"`
	AppID  int      `json:"app_id"`
	Roles  []string `json:"roles"`
}
