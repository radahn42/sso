package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/radahn42/sso/internal/domain/models"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrTokenExpired = errors.New("token expired")
)

// NewToken generates a new JWT token for a user and app.
func NewToken(userID int64, email string, appID int, roles []string, secret string, duration time.Duration) (string, error) {
	claims := &models.UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "sso-service",
			Subject:   fmt.Sprintf("%d", userID),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
		},
		UserID: userID,
		Email:  email,
		AppID:  appID,
		Roles:  roles,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(secret))
}

// ParseToken parses and validates a JWT token string.
// It returns models.UserClaims if the token is valid, otherwise an error.
func ParseToken(tokenString, secret string) (*models.UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.UserClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(*models.UserClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

func ParseTokenUnverified(tokenString string) (*models.UserClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &models.UserClaims{})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*models.UserClaims)
	if !ok {
		return nil, errors.New("invalid claims type")
	}
	return claims, nil
}
