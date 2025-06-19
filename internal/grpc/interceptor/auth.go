package interceptor

import (
	"context"
	"github.com/radahn42/sso/internal/lib/authctx"
	"log/slog"
	"strconv"
	"strings"

	"github.com/radahn42/sso/internal/domain/models"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type AppProvider interface {
	App(ctx context.Context, id int) (models.App, error)
}

type PermissionProvider interface {
	HasPermission(ctx context.Context, userID int64, permission string) (bool, error)
}

type TokenProvider interface {
	ValidateAccessToken(ctx context.Context, tokenStr, appSecret string) (*models.UserClaims, error)
}

func AuthInterceptor(
	log *slog.Logger,
	appProvider AppProvider,
	permProvider PermissionProvider,
	tokenProvider TokenProvider,
	protectedMethods map[string][]string,
) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		const op = "auth.AuthInterceptor"

		log := log.With(slog.String("op", op))

		requiredPerms, ok := protectedMethods[info.FullMethod]
		if !ok {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "metadata is not provided")
		}

		authHeaders := md.Get("authorization")
		if len(authHeaders) == 0 {
			return nil, status.Error(codes.Unauthenticated, "authorization header is not provided")
		}

		authHeader := authHeaders[0]
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return nil, status.Error(codes.Unauthenticated, "invalid authorization header format")
		}
		accessToken := parts[1]

		appIDHeaders := md.Get("x-app-id")
		if len(appIDHeaders) == 0 {
			return nil, status.Error(codes.InvalidArgument, "app id header (x-app-id) is not provided")
		}

		appID, err := strconv.Atoi(appIDHeaders[0])
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid app id format")
		}

		app, err := appProvider.App(ctx, appID)
		if err != nil {
			log.Error("failed to get app info", slog.Any("error", err))
			return nil, status.Errorf(codes.FailedPrecondition, "failed to get app info: %v", err)
		}

		claims, err := tokenProvider.ValidateAccessToken(ctx, accessToken, app.Secret)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "invalid access token: %v", err)
		}

		userID := claims.UserID

		if len(requiredPerms) > 0 {
			for _, perm := range requiredPerms {
				has, err := permProvider.HasPermission(ctx, userID, perm)
				if err != nil {
					return nil, status.Errorf(codes.Internal, "failed to check permissions: %v", err)
				}
				if !has {
					return nil, status.Errorf(codes.PermissionDenied, "user does not have required permission: %s", perm)
				}
			}
		}

		newCtx := authctx.SetAppID(ctx, appID)
		newCtx = authctx.SetUserID(newCtx, userID)

		return handler(newCtx, req)
	}
}
