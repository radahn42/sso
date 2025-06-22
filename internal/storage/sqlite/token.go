package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/radahn42/sso/internal/domain/models"
	"github.com/radahn42/sso/internal/storage"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

func (s *Storage) SaveRefreshToken(ctx context.Context, userID int64, appID int, token string, expiresAt int64) (int64, error) {
	const op = "storage.sqlite.SaveRefreshToken"

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO refresh_tokens (user_id, app_id, token, expires_at)
		VALUES (?, ?, ?, ?)`,
		userID, appID, token, expiresAt,
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

func (s *Storage) GetRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	const op = "storage.sqlite.RefreshToken"

	var rt models.RefreshToken
	err := s.db.QueryRowContext(ctx, `SELECT user_id, token, expires_at
		FROM refresh_tokens
		WHERE token = ?`, token).Scan(
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

func (s *Storage) SavePasswordResetToken(ctx context.Context, userID int64, tokenHash []byte, expiresAt time.Time) error {
	const op = "storage.sqlite.SavePasswordResetToken"

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
		userID, tokenHash, expiresAt,
	)
	if err != nil {
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
			return fmt.Errorf("%s: token already exists (hash collision?): %w", op, err)
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) GetPasswordResetToken(ctx context.Context, tokenHash []byte) (int64, time.Time, error) {
	const op = "storage.sqlite.GetPasswordResetToken"

	var (
		userID    int64
		expiresAt int64
	)
	err := s.db.QueryRowContext(ctx,
		"SELECT user_id, expires_at  FROM password_reset_tokens WHERE token_hash = ?", tokenHash,
	).Scan(&userID, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, time.Time{}, fmt.Errorf("%s: %w", op, storage.ErrResetTokenNotFound)
		}
	}

	if time.Now().Unix() > expiresAt {
		_ = s.DeletePasswordResetToken(ctx, tokenHash)
		return 0, time.Time{}, fmt.Errorf("%s: %w", op, storage.ErrResetTokenExpired)
	}

	return userID, time.Unix(expiresAt, 0), nil
}

func (s *Storage) DeletePasswordResetToken(ctx context.Context, tokenHash []byte) error {
	const op = "storage.sqlite.DeletePasswordResetToken"

	res, err := s.db.ExecContext(ctx,
		"DELETE FROM password_reset_tokens WHERE token_hash = ?", tokenHash,
	)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%s: %w", op, storage.ErrResetTokenNotFound)
	}

	return nil
}
