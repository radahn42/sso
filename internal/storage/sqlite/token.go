package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/radahn42/sso/internal/domain/models"
	"github.com/radahn42/sso/internal/storage"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

func (s *Storage) SaveRefreshToken(ctx context.Context, userID int64, token string, expiresAt int64) (int64, error) {
	const op = "storage.sqlite.SaveRefreshToken"

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO refresh_tokens (user_id, token, expires_at)
		VALUES (?, ?, ?)`,
		userID, token, expiresAt,
	)
	if err != nil {
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrAlreadyExists)
		}
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (s *Storage) DeleteRefreshToken(ctx context.Context, token string) error {
	const op = "storage.sqlite.DeleteRefreshToken"

	res, err := s.db.ExecContext(ctx,
		"DELETE FROM refresh_tokens WHERE token = ?", token,
	)
	if err != nil {
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY {
			return fmt.Errorf("%s: %w", op, storage.ErrForeignKeyViolation)
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%s: %w", op, storage.ErrNotFound)
	}

	return nil
}

func (s *Storage) DeleteUserTokens(ctx context.Context, userID int64) error {
	const op = "storage.sqlite.DeleteUserTokens"

	res, err := s.db.ExecContext(ctx,
		"DELETE FROM refresh_tokens WHERE user_id = ?", userID,
	)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%s: %w", op, storage.ErrNotFound)
	}

	return nil
}

func (s *Storage) RevokeAccessToken(ctx context.Context, jti string, expiresAt int64) error {
	const op = "storage.sqlite.RevokeAccessToken"

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO revoked_tokens (token_jti, expires_at) VALUES (?, ?)", jti, expiresAt,
	)
	if err != nil {
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY {
			return fmt.Errorf("%s: %w", op, storage.ErrForeignKeyViolation)
		}
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
			return fmt.Errorf("%s: %w", op, storage.ErrAlreadyExists)
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) IsAccessTokenRevoked(ctx context.Context, jti string) (bool, error) {
	const op = "storage.sqlite.IsAccessTokenRevoked"

	var revoked bool
	err := s.db.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE token_jti = ?)", jti,
	).Scan(&revoked)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return revoked, nil
}

func (s *Storage) RefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	const op = "storage.sqlite.RefreshToken"

	var rt models.RefreshToken
	err := s.db.QueryRowContext(ctx, `SELECT user_id, token, expires_at
		FROM refresh_tokens
		WHERE token = $1`, token).Scan(
		&rt.UserID,
		&rt.Token,
		&rt.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &rt, nil
}
