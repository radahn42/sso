package token

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/radahn42/sso/internal/domain/models"
	"github.com/radahn42/sso/internal/lib/jwt"
	"github.com/radahn42/sso/internal/storage"
	"log/slog"
	"time"
)

var (
	ErrInvalidToken = jwt.ErrInvalidToken
	ErrTokenExpired = jwt.ErrTokenExpired
	ErrTokenRevoked = errors.New("token revoked")
)

type Saver interface {
	SaveRefreshToken(ctx context.Context, userID int64, token string, expiresAt int64) (int64, error)
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteUserTokens(ctx context.Context, userID int64) error
	RevokeAccessToken(ctx context.Context, jti string, expiresAt int64) error
}

type Provider interface {
	IsAccessTokenRevoked(ctx context.Context, jti string) (bool, error)
}

type Service struct {
	log             *slog.Logger
	saver           Saver
	provider        Provider
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

func New(
	log *slog.Logger,
	saver Saver,
	provider Provider,
	accessTokenTTL time.Duration,
	refreshTokenTTL time.Duration,
) *Service {
	return &Service{
		log:             log,
		saver:           saver,
		provider:        provider,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
	}
}

func (s *Service) GenerateTokens(
	ctx context.Context,
	user models.User,
	app models.App,
	roles []string,
) (accessToken, refreshToken string, err error) {
	const op = "token.GenerateTokens"
	log := s.log.With(
		slog.String("op", op),
		slog.Int64("user_id", user.ID),
		slog.String("app_name", app.Name),
	)

	accessToken, err = jwt.NewToken(user, app, roles, s.accessTokenTTL)
	if err != nil {
		log.Error("failed to generate access token", slog.Any("error", err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	refreshToken = uuid.NewString()
	expiresAt := time.Now().Add(s.refreshTokenTTL).Unix()

	_, err = s.saver.SaveRefreshToken(ctx, user.ID, refreshToken, expiresAt)
	if err != nil {
		log.Error("failed to save refresh token", slog.Any("error", err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("tokens generated successfully")
	return
}

func (s *Service) ValidateAccessToken(ctx context.Context, tokenStr, appSecret string) (*models.UserClaims, error) {
	const op = "token.ValidateAccessToken"
	log := s.log.With(slog.String("op", op))

	claims, err := jwt.ParseToken(tokenStr, appSecret)
	if err != nil {
		if errors.Is(err, jwt.ErrInvalidToken) {
			log.Warn("invalid access token", slog.Any("error", err))
			return nil, fmt.Errorf("%s: %w", op, ErrInvalidToken)
		}
		if errors.Is(err, jwt.ErrTokenExpired) {
			log.Warn("access token expired", slog.Any("error", err))
			return nil, fmt.Errorf("%s: %w", op, ErrTokenExpired)
		}
		log.Error("failed to parse access token", slog.Any("error", err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if claims.ID != "" {
		revoked, err := s.provider.IsAccessTokenRevoked(ctx, claims.ID)
		if err != nil {
			log.Error("failed to check if access token is revoked", slog.Any("error", err))
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		if revoked {
			log.Warn("access token is revoked", slog.String("jti", claims.ID))
			return nil, fmt.Errorf("%s: %w", op, ErrTokenRevoked)
		}
	} else {
		log.Warn("access token has no JTI, cannot check for revocation")
	}

	log.Info(
		"access token validated successfully",
		slog.String("user_email", claims.Email),
		slog.Int("app_id", claims.AppID),
	)
	return claims, nil
}

func (s *Service) RevokeAccessToken(ctx context.Context, tokenStr, appSecret string) error {
	const op = "token.RevokeAccessToken"
	log := s.log.With(slog.String("op", op))

	claims, err := jwt.ParseToken(tokenStr, appSecret)
	if err != nil {
		if errors.Is(err, jwt.ErrInvalidToken) {
			log.Warn("invalid token for revocation", slog.Any("error", err))
			return fmt.Errorf("%s: %w", op, ErrInvalidToken)
		}
		if errors.Is(err, jwt.ErrTokenExpired) {
			log.Warn("attempt to revoke an expired token", slog.Any("error", err))
		}
		log.Error("failed to parse token for revocation", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	if claims.ID == "" || claims.ExpiresAt == nil {
		log.Warn(
			"token missing JTI or ExpiresAt, cannot revoke",
			slog.String("token_str_prefix", tokenStr[:10]+"..."),
		)
		return fmt.Errorf("%s: %w", op, ErrInvalidToken)
	}

	err = s.saver.RevokeAccessToken(ctx, claims.ID, claims.ExpiresAt.Unix())
	if err != nil {
		log.Error(
			"failed to save revoked access token JTI",
			slog.String("jti", claims.ID),
			slog.Any("error", err),
		)
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("access token revoked successfully", slog.String("jti", claims.ID))
	return nil
}

func (s *Service) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	const op = "token.RevokeRefreshToken"
	log := s.log.With(slog.String("op", op))

	err := s.saver.DeleteRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			log.Warn(
				"refresh token not found for revocation",
				slog.String("token_prefix", refreshToken[:5]+"..."),
			)
		}
		log.Error("failed to delete refresh token", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("refresh token revoked successfully")
	return nil
}

func (s *Service) RevokeAllRefreshTokens(ctx context.Context, userID int64) error {
	const op = "token.RevokeAllRefreshTokens"
	log := s.log.With(slog.String("op", op), slog.Int64("user_id", userID))

	err := s.saver.DeleteUserTokens(ctx, userID)
	if err != nil {
		log.Error("failed to delete all user refresh tokens", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("all refresh tokens revoked for user")
	return nil
}
