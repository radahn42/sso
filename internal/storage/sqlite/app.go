package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/radahn42/sso/internal/domain/models"
	"github.com/radahn42/sso/internal/storage"
)

func (s *Storage) App(ctx context.Context, appID int) (models.App, error) {
	const op = "storage.sqlite.App"

	var app models.App
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, secret FROM apps WHERE id = ?", appID,
	).Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	return app, nil
}

func (s *Storage) AppByName(ctx context.Context, name string) (models.App, error) {
	const op = "storage.sqlite.AppByName"

	var app models.App
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, secret FROM apps WHERE name = ?", name,
	).Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	return app, nil
}
