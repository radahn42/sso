package token

import (
	"context"
	"errors"
	"fmt"
	"github.com/radahn42/sso/internal/config"
	"github.com/radahn42/sso/internal/lib/authctx"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/radahn42/sso/internal/domain/models"
	"github.com/radahn42/sso/internal/lib/jwt"
	"github.com/radahn42/sso/internal/storage"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrTokenExpired = errors.New("token is expired")
	ErrTokenRevoked = errors.New("token revoked")
)

type Saver interface {
	SaveRefreshToken(ctx context.Context, userID int64, appID int, token string, expiresAt int64) (int64, error)
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteUserTokens(ctx context.Context, userID int64) error
	RevokeAccessToken(ctx context.Context, jti string, expiresAt int64) error
}

type Provider interface {
	IsAccessTokenRevoked(ctx context.Context, jti string) (bool, error)
	GetRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error)
}

type UserProvider interface {
	UserByID(ctx context.Context, userID int64) (models.User, error)
}

type RoleProvider interface {
	UserRoles(ctx context.Context, userID int64) ([]models.Role, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}

type Service struct {
	log          *slog.Logger
	cfg          *config.Config
	saver        Saver
	provider     Provider
	userProvider UserProvider
	roleProvider RoleProvider
	appProvider  AppProvider
}

func New(
	log *slog.Logger,
	cfg *config.Config,
	saver Saver,
	provider Provider,
	userProvider UserProvider,
	roleProvider RoleProvider,
	appProvider AppProvider,
) *Service {
	return &Service{
		log:          log,
		cfg:          cfg,
		saver:        saver,
		provider:     provider,
		userProvider: userProvider,
		roleProvider: roleProvider,
		appProvider:  appProvider,
	}
}

func (s *Service) GenerateTokens(
	ctx context.Context,
	payload Payload,
) (accessToken, refreshToken string, err error) {
	const op = "token.GenerateTokens"
	log := s.log.With(
		slog.String("op", op),
		slog.Int64("user_id", payload.UserID),
		slog.Int("app_id", payload.AppID),
	)

	accessToken, err = jwt.NewToken(
		payload.UserID,
		payload.Email,
		payload.AppID,
		payload.Roles,
		payload.Secret,
		s.cfg.AccessTokenTTL,
	)
	if err != nil {
		log.Error("failed to generate access token", slog.Any("error", err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	refreshToken = uuid.NewString()
	expiresAt := time.Now().Add(s.cfg.RefreshTokenTTL).Unix()

	_, err = s.saver.SaveRefreshToken(ctx, payload.UserID, payload.AppID, refreshToken, expiresAt)
	if err != nil {
		log.Error("failed to save refresh token", slog.Any("error", err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("tokens generated successfully")
	return accessToken, refreshToken, nil
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

func (s *Service) RefreshTokens(ctx context.Context, refreshToken string) (newAccessToken, newRefreshToken string, err error) {
	const op = "token.RefreshTokens"
	log := s.log.With(slog.String("op", op))

	log.Info("starting token refresh process")

	rt, err := s.provider.GetRefreshToken(ctx, refreshToken)
	if err != nil {
		log.Error("failed to get refresh token from storage", slog.Any("error", err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	if time.Now().Unix() > rt.ExpiresAt {
		log.Warn("refresh token expired", slog.Int64("expires_at", rt.ExpiresAt))
		return "", "", fmt.Errorf("%s: %w", op, ErrTokenExpired)
	}

	payload, err := s.buildPayload(ctx, rt.UserID)
	if err != nil {
		log.Error("failed to build payload", slog.Any("error", err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	newAccessToken, newRefreshToken, err = s.GenerateTokens(ctx, payload)
	if err != nil {
		log.Error("failed to generate new tokens", slog.Any("error", err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	err = s.saver.DeleteRefreshToken(ctx, refreshToken)
	if err != nil {
		log.Error("failed to delete old refresh token", slog.Any("error", err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("tokens refreshed successfully", slog.Int64("user_id", rt.UserID))
	return
}

func (s *Service) buildPayload(ctx context.Context, userID int64) (Payload, error) {
	const op = "token.buildPayload"
	log := s.log.With(slog.String("op", op), slog.Int64("user_id", userID))

	user, err := s.userProvider.UserByID(ctx, userID)
	if err != nil {
		log.Error("failed to get user by ID", slog.Any("error", err))
		return Payload{}, fmt.Errorf("%s: %w", op, err)
	}

	appID, ok := authctx.AppID(ctx)
	if !ok {
		log.Error("failed to get app ID from context")
		return Payload{}, fmt.Errorf("%s: failed to get app ID from ctx", op)
	}

	app, err := s.appProvider.App(ctx, appID)
	if err != nil {
		log.Error("failed to get app", slog.Any("error", err))
		return Payload{}, fmt.Errorf("%s: %w", op, err)
	}

	roles, err := s.roleProvider.UserRoles(ctx, user.ID)
	if err != nil {
		log.Error("failed to get user roles", slog.Any("error", err))
		return Payload{}, fmt.Errorf("%s: %w", op, err)
	}

	roleNames := make([]string, 0, len(roles))
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}

	return Payload{
		UserID: user.ID,
		Email:  user.Email,
		AppID:  app.ID,
		Roles:  roleNames,
		Secret: app.Secret,
	}, nil
}
