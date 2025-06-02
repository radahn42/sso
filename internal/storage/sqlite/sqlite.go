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

type Storage struct {
	db *sql.DB
}

// New creates a new instance of the SQLite storage.
func New(storagePath string) (*Storage, error) {
	const op = "storage.sqlite.New"

	db, err := sql.Open("sqlite", storagePath+"?_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &Storage{db: db}, nil
}

func (s *Storage) Close() error {
	return s.db.Close()
}

// SaveUser saves a new user to the database.
func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "storage.sqlite.SaveUser"

	res, err := s.db.ExecContext(ctx,
		"INSERT INTO users (email, pass_hash) VALUES (?, ?)", email, passHash,
	)
	if err != nil {
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserExists)
		}
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

// User retrieves a user by email.
func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	const op = "storage.sqlite.User"

	var user models.User
	err := s.db.QueryRowContext(ctx,
		"SELECT id, email, pass_hash FROM users WHERE email = ?", email,
	).Scan(&user.ID, &user.Email, &user.PassHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

// UserByID retrieves a user by ID.
func (s *Storage) UserByID(ctx context.Context, userID int64) (models.User, error) {
	const op = "storage.sqlite.UserByID"

	var user models.User
	err := s.db.QueryRowContext(ctx,
		"SELECT id, email, pass_hash FROM users WHERE id = ?", userID,
	).Scan(&user.ID, &user.Email, &user.PassHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

func (s *Storage) UpdateUser(ctx context.Context, user models.User) error {
	const op = "storage.sqlite.UpdateUser"

	res, err := s.db.ExecContext(ctx,
		"UPDATE users SET email = ? WHERE id = ?", user.Email, user.ID,
	)
	if err != nil {
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
			return fmt.Errorf("%s: %w", op, storage.ErrUserExists)
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
	}

	return nil
}

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
