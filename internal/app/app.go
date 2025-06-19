package app

import (
	grpcapp "github.com/radahn42/sso/internal/app/grpc"
	"github.com/radahn42/sso/internal/config"
	"github.com/radahn42/sso/internal/services/app"
	"github.com/radahn42/sso/internal/services/auth"
	"github.com/radahn42/sso/internal/services/permission"
	"github.com/radahn42/sso/internal/services/role"
	"github.com/radahn42/sso/internal/services/token"
	"github.com/radahn42/sso/internal/storage/sqlite"
	"log/slog"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(
	log *slog.Logger,
	cfg *config.Config,
) *App {
	storage, err := sqlite.New(cfg.StoragePath)
	if err != nil {
		panic(err)
	}

	tokenService := token.New(log, cfg, storage, storage, storage, storage, storage)
	authService := auth.New(log, storage, storage, storage, storage, storage, tokenService)
	roleService := role.New(log, storage, storage, storage, storage)
	permService := permission.New(log, storage, storage, storage, storage, storage)
	appService := app.New(log, storage)

	grpcApp := grpcapp.New(log, cfg, authService, roleService, permService, appService, permService, tokenService)

	return &App{
		GRPCSrv: grpcApp,
	}
}
