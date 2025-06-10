package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/radahn42/sso/internal/domain/models"
	"github.com/radahn42/sso/internal/storage"
)

var (
	ErrAppNotFound = errors.New("app not found")
)

type Provider interface {
	App(ctx context.Context, id int) (models.App, error)
	AppByName(ctx context.Context, name string) (models.App, error)
}

type App struct {
	log         *slog.Logger
	appProvider Provider
}

func New(log *slog.Logger, appProvider Provider) *App {
	return &App{
		log:         log,
		appProvider: appProvider,
	}
}

func (a *App) App(ctx context.Context, id int) (models.App, error) {
	const op = "app.App"

	app, err := a.appProvider.App(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return models.App{}, fmt.Errorf("%s: %w", op, ErrAppNotFound)
		}
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	return app, nil
}

func (a *App) AppByName(ctx context.Context, name string) (models.App, error) {
	const op = "app.AppByName"

	app, err := a.appProvider.AppByName(ctx, name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return models.App{}, fmt.Errorf("%s: %w", op, ErrAppNotFound)
		}
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	return app, nil
}
