package app

import (
	"log/slog"
	"time"

	grpcapp "github.com/radahn42/sso/internal/app/grpc"
	"github.com/radahn42/sso/internal/services/auth"
	"github.com/radahn42/sso/internal/services/permission"
	"github.com/radahn42/sso/internal/services/role"
	"github.com/radahn42/sso/internal/storage/sqlite"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(
	log *slog.Logger,
	grpcPort int,
	grpcHost string,
	storagePath string,
	tokenTTL time.Duration,
) *App {
	storage, err := sqlite.New(storagePath)
	if err != nil {
		panic(err)
	}

	authService := auth.New(log, storage, storage, storage, storage, storage, storage, tokenTTL)
	roleService := role.New(log, storage, storage, storage, storage)
	permService := permission.New(log, storage, storage, storage, storage, storage)

	grpcApp := grpcapp.New(log, authService, roleService, permService, grpcPort, grpcHost)

	return &App{
		GRPCSrv: grpcApp,
	}
}
