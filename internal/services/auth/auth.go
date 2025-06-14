package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/radahn42/sso/internal/domain/models"
	"github.com/radahn42/sso/internal/lib/jwt"
	"github.com/radahn42/sso/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidAppID       = errors.New("invalid app id")
	ErrUserExists         = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")
)

type UserSaver interface {
	SaveUser(ctx context.Context, email string, passHash []byte) (uid int64, err error)
	UpdateUser(ctx context.Context, user models.User) error
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	UserByID(ctx context.Context, userID int64) (models.User, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
	AppByName(ctx context.Context, name string) (models.App, error)
}

type RoleProvider interface {
	UserRoles(ctx context.Context, userID int64) ([]models.Role, error)
}

type PermissionProvider interface {
	UserPermissions(ctx context.Context, userID int64) ([]models.Permission, error)
}

type TokenSaver interface {
	RevokeAccessToken(ctx context.Context, jti string, expiresAt int64) error
}

type Auth struct {
	log          *slog.Logger
	usrSaver     UserSaver
	usrProvider  UserProvider
	appProvider  AppProvider
	roleProvider RoleProvider
	permProvider PermissionProvider
	tokenSaver   TokenSaver
	tokenTTL     time.Duration
}

// New returns a new instance of the Auth service.
func New(
	log *slog.Logger,
	usrSaver UserSaver,
	usrProvider UserProvider,
	appProvider AppProvider,
	roleProvider RoleProvider,
	permProvider PermissionProvider,
	tokenSaver TokenSaver,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		log:          log,
		usrSaver:     usrSaver,
		usrProvider:  usrProvider,
		appProvider:  appProvider,
		roleProvider: roleProvider,
		permProvider: permProvider,
		tokenSaver:   tokenSaver,
		tokenTTL:     tokenTTL,
	}
}

// Login checks if user with given credentials exists in the system and returns a JWT token.
func (a *Auth) Login(ctx context.Context, email string, password string, appID int) (string, error) {
	const op = "auth.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)
	log.Info("attempting to login user")

	user, err := a.usrProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", slog.Any("error", err))
			return "", fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		a.log.Error("failed to get user", slog.Any("error", err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Info("invalid credentials", slog.Any("error", err))
		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			a.log.Warn("app not found", slog.Any("error", err))

			return "", fmt.Errorf("%s: %w", op, ErrInvalidAppID)
		}

		return "", fmt.Errorf("%s: %w", op, err)
	}

	userRoles, err := a.roleProvider.UserRoles(ctx, user.ID)
	if err != nil {
		a.log.Error("failed to get user roles for JWT claims", slog.Any("error", err))
		return "", fmt.Errorf("%s: failed to get user roles: %w", op, err)
	}
	roleNames := make([]string, 0, len(userRoles))
	for _, role := range userRoles {
		roleNames = append(roleNames, role.Name)
	}

	log.Info("user logged in successfully")

	token, err := jwt.NewToken(user, app, roleNames, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token", slog.Any("error", err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

// RegisterUser registers new user in the system and returns user ID.
func (a *Auth) RegisterUser(ctx context.Context, email string, password string) (int64, error) {
	const op = "auth.RegisterUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)
	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash", slog.Any("error", err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.usrSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			a.log.Warn("user already exists", slog.Any("error", ErrUserExists))
			return 0, fmt.Errorf("%s: %w", op, err)
		}

		log.Error("failed to save user", slog.Any("error", err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user registered successfully")
	return id, nil
}

// ValidateToken parses and validates a JWT token.
// It returns models.UserClaims on success.
// If token is invalid or expired, it returns an appropriate error.
func (a *Auth) ValidateToken(ctx context.Context, tokenString string) (*models.UserClaims, error) {
	const op = "auth.ValidateToken"
	log := a.log.With(slog.String("op", op))

	claimsUnverified, err := jwt.ParseTokenUnverified(tokenString)
	if err != nil {
		log.Warn("failed to parse token unverified", slog.Any("error", err))
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidToken)
	}

	app, err := a.appProvider.App(ctx, claimsUnverified.AppID)
	if err != nil {
		log.Warn("invalid app id in token", slog.Any("error", err))
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidAppID)
	}

	claims, err := jwt.ParseToken(tokenString, app.Secret)
	if err != nil {
		if errors.Is(err, jwt.ErrInvalidToken) {
			log.Warn("invalid token", slog.Any("error", err))
			return nil, fmt.Errorf("%s: %w", op, ErrInvalidToken)
		}
		if errors.Is(err, jwt.ErrTokenExpired) {
			log.Warn("token expired", slog.Any("error", err))
			return nil, fmt.Errorf("%s: %w", op, ErrTokenExpired)
		}
		log.Error("failed to parse token", slog.Any("error", err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("token validated successfully",
		slog.Int64("user_id", claims.UserID),
		slog.String("email", claims.Email),
		slog.Int("app_id", claims.AppID),
		slog.Any("roles", claims.Roles),
	)

	return claims, nil
}

func (a *Auth) RequestPasswordReset(ctx context.Context, email string) error {
	//TODO implement me
	panic("implement me")
}

func (a *Auth) ConfirmPasswordReset(ctx context.Context, email, resetToken, newPassword string) error {
	//TODO implement me
	panic("implement me")
}

func (a *Auth) ChangePassword(ctx context.Context, userID int64, oldPassword, newPassword string) error {
	//TODO implement me
	panic("implement me")
}

func (a *Auth) Logout(ctx context.Context, token string) error {
	const op = "auth.Logout"
	log := a.log.With(slog.String("op", op))

	claimsUnverified, err := jwt.ParseTokenUnverified(token)
	if err != nil {
		log.Warn("failed to parse token unverified", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, ErrInvalidToken)
	}

	app, err := a.appProvider.App(ctx, claimsUnverified.AppID)
	if err != nil {
		log.Warn("invalid app id in token", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, ErrInvalidAppID)
	}

	claims, err := jwt.ParseToken(token, app.Secret)
	if err != nil {
		if errors.Is(err, jwt.ErrInvalidToken) {
			log.Warn("attempted to logout with an invalid token", slog.Any("error", err))
			return nil
		}
		if errors.Is(err, jwt.ErrTokenExpired) {
			log.Warn("attempted to logout with an expired token", slog.Any("error", err))
			return nil
		}
		log.Error("failed to parse token for logout", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	if claims.ID == "" || claims.ExpiresAt == nil {
		log.Warn(
			"token missing JTI or ExpiresAt, cannot revoke",
			slog.String("token_str_prefix", token[:10]+"..."),
		)
		return fmt.Errorf("%s: %w", op, ErrInvalidToken)
	}

	err = a.tokenSaver.RevokeAccessToken(ctx, claims.ID, claims.ExpiresAt.Unix())
	if err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			return nil
		}
		log.Error(
			"failed to revoke access token",
			slog.String("jti", claims.ID),
			slog.Any("error", err),
		)
		return fmt.Errorf("%s: failed to revoke token: %w", op, err)
	}

	log.Info(
		"access token successfully revoked",
		slog.String("jti", claims.ID),
	)
	return nil
}
