package app

import (
	grpcapp "github.com/radahn42/sso/internal/app/grpc"
	"github.com/radahn42/sso/internal/services/auth"
	"github.com/radahn42/sso/internal/storage/sqlite"
	"log/slog"
	"time"
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

	authService := auth.New(log, storage, storage, storage, tokenTTL)

	grpcApp := grpcapp.New(log, authService, grpcPort, grpcHost)

	return &App{
		GRPCSrv: grpcApp,
	}
}
