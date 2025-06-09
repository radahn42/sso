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

func (s *Storage) AddPermissionToRole(ctx context.Context, roleID, permissionID int64) error {
	const op = "storage.sqlite.AddPermissionToRole"

	res, err := s.db.ExecContext(ctx,
		"INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)", roleID, permissionID,
	)
	if err != nil {
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
			return fmt.Errorf("%s: %w", op, storage.ErrAlreadyExists)
		}
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY {
			return fmt.Errorf("%s: %w", op, storage.ErrNotFound)
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%s: failed to add permission to role, no rows affected: %w", op, storage.ErrInternal)
	}

	return nil
}

func (s *Storage) RemovePermissionFromRole(ctx context.Context, roleID, permissionID int64) error {
	const op = "storage.sqlite.RemovePermissionFromRole"

	res, err := s.db.ExecContext(ctx,
		"DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?", roleID, permissionID,
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

func (s *Storage) SavePermission(ctx context.Context, name, description string) (int64, error) {
	const op = "storage.sqlite.SavePermission"

	res, err := s.db.ExecContext(ctx,
		"INSERT INTO permissions (name, description) VALUES (?, ?)", name, description,
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

func (s *Storage) DeletePermission(ctx context.Context, permissionID int64) error {
	const op = "storage.sqlite.DeletePermission"

	res, err := s.db.ExecContext(ctx,
		"DELETE FROM permissions WHERE id = ?", permissionID,
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

func (s *Storage) UpdatePermission(ctx context.Context, permissionID int64, name, description string) error {
	const op = "storage.sqlite.UpdatePermission"

	res, err := s.db.ExecContext(ctx,
		"UPDATE permissions SET name = ?, description = ? WHERE id = ?",
		name, description, permissionID,
	)
	if err != nil {
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
			return fmt.Errorf("%s: %w", op, storage.ErrAlreadyExists)
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

func (s *Storage) PermissionByID(ctx context.Context, permissionID int64) (*models.Permission, error) {
	const op = "storage.sqlite.PermissionByID"

	var perm models.Permission
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, description FROM permissions WHERE id = ?", permissionID,
	).Scan(&perm.ID, &perm.Name, &perm.Description)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, storage.ErrNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &perm, nil
}

func (s *Storage) PermissionByName(ctx context.Context, name string) (models.Permission, error) {
	const op = "storage.sqlite.PermissionByName"

	var perm models.Permission
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, description FROM permissions WHERE name = ?", name,
	).Scan(&perm.ID, &perm.Name, &perm.Description)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Permission{}, fmt.Errorf("%s: %w", op, storage.ErrNotFound)
		}
		return models.Permission{}, fmt.Errorf("%s: %w", op, err)
	}

	return perm, nil
}

func (s *Storage) AllPermissions(ctx context.Context) ([]models.Permission, error) {
	const op = "storage.sqlite.AllPermissions"

	rows, err := s.db.QueryContext(ctx,
		"SELECT id, name, description FROM permissions",
	)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	var perms []models.Permission
	for rows.Next() {
		var perm models.Permission
		if err := rows.Scan(&perm.ID, &perm.Name, &perm.Description); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		perms = append(perms, perm)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return perms, nil
}

func (s *Storage) HasPermission(ctx context.Context, userID int64, permission string) (bool, error) {
	const op = "storage.sqlite.HasPermission"

	var exists bool
	err := s.db.QueryRowContext(ctx, `
	SELECT EXISTS(
		SELECT 1
		FROM user_roles ur
		JOIN role_permissions rp ON ur.role_id = rp.role_id
		JOIN permissions p ON rp.permission_id = p.id
		WHERE ur.user_id = ? AND p.name = ?
		limit 1
	)`, userID, permission).Scan(&exists)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("%s: query error: %w", op, err)
	}

	return true, nil
}

func (s *Storage) UserPermissions(ctx context.Context, userID int64) ([]models.Permission, error) {
	const op = "storage.sqlite.UserPermissions"

	rows, err := s.db.QueryContext(ctx, `
		SELECT p.id, p.name, p.description
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		INNER JOIN user_roles ur ON rp.role_id = ur.role_id
		WHERE ur.user_id = ?`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("%s: query error: %w", op, err)
	}
	defer rows.Close()

	var perms []models.Permission
	for rows.Next() {
		var perm models.Permission
		if err := rows.Scan(&perm.ID, &perm.Name, &perm.Description); err != nil {
			return nil, fmt.Errorf("%s: scan error: %w", op, err)
		}
		perms = append(perms, perm)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: rows error: %w", op, err)
	}

	return perms, nil
}
