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

func (s *Storage) SaveRole(ctx context.Context, name, description string) (int64, error) {
	const op = "storage.sqlite.SaveRole"

	res, err := s.db.ExecContext(ctx,
		"INSERT INTO roles (name, description) VALUES (?, ?)", name, description,
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

func (s *Storage) DeleteRole(ctx context.Context, roleID int64) error {
	const op = "storage.sqlite.DeleteRole"

	res, err := s.db.ExecContext(ctx,
		"DELETE FROM roles WHERE id = ?", roleID,
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

func (s *Storage) UpdateRole(ctx context.Context, role models.Role) error {
	const op = "storage.sqlite.UpdateRole"

	res, err := s.db.ExecContext(ctx,
		"UPDATE roles SET name = ?, description = ? WHERE id = ?",
		role.Name, role.Description, role.ID,
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

func (s *Storage) AssignUserRole(ctx context.Context, userID, roleID int64) error {
	const op = "storage.sqlite.AssignUserRole"

	res, err := s.db.ExecContext(ctx,
		"INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", userID, roleID,
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
		return fmt.Errorf("%s: failed to assign user role, no rows affected: %w", op, storage.ErrInternal)
	}

	return nil
}

func (s *Storage) RevokeUserRole(ctx context.Context, userID, roleID int64) error {
	const op = "storage.sqlite.RevokeUserRole"

	res, err := s.db.ExecContext(ctx,
		"DELETE FROM user_roles WHERE user_id = ? AND role_id = ?", userID, roleID,
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

func (s *Storage) RoleByID(ctx context.Context, roleID int64) (models.Role, error) {
	const op = "storage.sqlite.RoleByID"

	var role models.Role
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, description FROM roles WHERE id = ?", roleID,
	).Scan(&role.ID, &role.Name, &role.Description)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Role{}, fmt.Errorf("%s: %w", op, storage.ErrNotFound)
		}
		return models.Role{}, fmt.Errorf("%s: %w", op, err)
	}

	return role, nil
}

func (s *Storage) RoleByName(ctx context.Context, name string) (models.Role, error) {
	const op = "storage.sqlite.RoleByName"

	var role models.Role
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, description FROM roles WHERE name = ?", name,
	).Scan(&role.ID, &role.Name, &role.Description)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Role{}, fmt.Errorf("%s: %w", op, storage.ErrNotFound)
		}
		return models.Role{}, fmt.Errorf("%s: %w", op, err)
	}

	return role, nil
}

func (s *Storage) AllRoles(ctx context.Context) ([]models.Role, error) {
	const op = "storage.sqlite.AllRoles"

	rows, err := s.db.QueryContext(ctx,
		"SELECT id, name, description FROM roles",
	)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	var roles []models.Role
	for rows.Next() {
		var role models.Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		roles = append(roles, role)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return roles, nil
}

func (s *Storage) UserRoles(ctx context.Context, userID int64) ([]models.Role, error) {
	const op = "storage.sqlite.UserRoles"

	rows, err := s.db.QueryContext(ctx, `
		SELECT r.id, r.name, r.description
		FROM roles r
		INNER JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = ?`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	var roles []models.Role
	for rows.Next() {
		var role models.Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		roles = append(roles, role)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return roles, nil
}

func (s *Storage) RolePermissions(ctx context.Context, roleID int64) ([]models.Permission, error) {
	const op = "storage.sqlite.RolePermissions"

	rows, err := s.db.QueryContext(ctx, `
		SELECT p.id, p.name, p.description
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = ?`, roleID,
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
