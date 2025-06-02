package role

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/radahn42/sso/internal/domain/models"
	"github.com/radahn42/sso/internal/storage"
)

var (
	ErrRoleNotFound       = errors.New("role not found")
	ErrRoleExists         = errors.New("role already exists")
	ErrUserAlreadyInRole  = errors.New("user already has this role")
	ErrUserNotInRole      = errors.New("user does not have this role")
	ErrPermissionNotFound = errors.New("permission not found")
)

type Saver interface {
	SaveRole(ctx context.Context, name string, description string) (roleID int64, err error)
	DeleteRole(ctx context.Context, roleID int64) error
	UpdateRole(ctx context.Context, role models.Role) error
	AssignUserRole(ctx context.Context, userID, roleID int64) error
	RevokeUserRole(ctx context.Context, userID, roleID int64) error
}

type Provider interface {
	RoleByID(ctx context.Context, roleID int64) (models.Role, error)
	RoleByName(ctx context.Context, name string) (models.Role, error)
	AllRoles(ctx context.Context) ([]models.Role, error)
	UserRoles(ctx context.Context, userID int64) ([]models.Role, error)
	RolePermissions(ctx context.Context, roleID int64) ([]models.Permission, error)
}

type UserProvider interface {
	UserByID(ctx context.Context, userID int64) (models.User, error)
}

type PermissionProvider interface {
	PermissionByID(ctx context.Context, permissionID int64) (*models.Permission, error)
	PermissionByName(ctx context.Context, name string) (models.Permission, error)
	AllPermissions(ctx context.Context) ([]models.Permission, error)
}

type Service struct {
	log                *slog.Logger
	roleSaver          Saver
	roleProvider       Provider
	userProvider       UserProvider
	permissionProvider PermissionProvider
}

func New(
	log *slog.Logger,
	roleSaver Saver,
	roleProvider Provider,
	userProvider UserProvider,
	permissionProvider PermissionProvider,
) *Service {
	return &Service{
		log:                log,
		roleSaver:          roleSaver,
		roleProvider:       roleProvider,
		userProvider:       userProvider,
		permissionProvider: permissionProvider,
	}
}

func (s *Service) CreateRole(ctx context.Context, name, description string) (int64, error) {
	const op = "role.CreateRole"
	log := s.log.With(slog.String("op", op), slog.String("name", name))

	_, err := s.roleProvider.RoleByName(ctx, name)
	if err == nil {
		log.Warn("role already exists")
		return 0, fmt.Errorf("%s: %w", op, ErrRoleExists)
	}
	if !errors.Is(err, storage.ErrNotFound) {
		log.Error("failed to check existing role", slog.Any("error", err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	roleID, err := s.roleSaver.SaveRole(ctx, name, description)
	if err != nil {
		log.Error("failed to save role", slog.Any("error", err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("role created successfully", slog.Int64("role_id", roleID))
	return roleID, nil
}

func (s *Service) DeleteRole(ctx context.Context, roleID int64) error {
	const op = "role.DeleteRole"
	log := s.log.With(slog.String("op", op), slog.Int64("role_id", roleID))

	_, err := s.roleProvider.RoleByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			log.Warn("role not found for deletion")
			return fmt.Errorf("%s: %w", op, ErrRoleNotFound)
		}
		log.Error("failed to get role by ID before deletion", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	err = s.roleSaver.DeleteRole(ctx, roleID)
	if err != nil {
		if errors.Is(err, storage.ErrForeignKeyViolation) {
			log.Error(
				"cannot delete role due to foreign key violation (e.g., assigned to users)",
				slog.Any("error", err),
			)
			return fmt.Errorf("%s: role is currently assigned to user or has permissions: %w", op, err)
		}
		log.Error("failed to delete role", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("role deleted successfully", slog.Int64("role_id", roleID))
	return nil
}

func (s *Service) UpdateRole(ctx context.Context, roleID int64, name, description string) error {
	const op = "role.UpdateRole"
	log := s.log.With(slog.String("op", op), slog.Int64("role_id", roleID))

	existingRole, err := s.roleProvider.RoleByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			log.Warn("role not found for update")
			return fmt.Errorf("%s: %w", op, ErrRoleNotFound)
		}
		log.Error("failed to get role by ID", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	if name != "" && name != existingRole.Name {
		_, err := s.roleProvider.RoleByName(ctx, name)
		if err == nil {
			log.Warn("new role name already exists")
			return fmt.Errorf("%s: %w", op, ErrRoleExists)
		}
		if !errors.Is(err, storage.ErrNotFound) {
			log.Error("failed to check new role name for conflict", slog.Any("error", err))
			return fmt.Errorf("%s: %w", op, err)
		}
	}

	updatedRole := models.Role{
		ID:          roleID,
		Name:        name,
		Description: description,
	}

	err = s.roleSaver.UpdateRole(ctx, updatedRole)
	if err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			return fmt.Errorf("%s: %w", op, ErrRoleExists)
		}
		log.Error("failed to update role", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("role updated successfully")
	return nil
}

func (s *Service) AssignRoleToUser(ctx context.Context, userID, roleID int64) error {
	const op = "role.AssignRoleToUser"
	log := s.log.With(slog.String("op", op), slog.Int64("user_id", userID), slog.Int64("role_id", roleID))

	_, err := s.userProvider.UserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return fmt.Errorf("%s: user not found: %w", op, storage.ErrUserNotFound)
		}
		return fmt.Errorf("%s: failed to get user: %w", op, err)
	}

	_, err = s.roleProvider.RoleByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("%s: role not found: %w", op, ErrRoleNotFound)
		}
		return fmt.Errorf("%s: failed to get role: %w", op, err)
	}

	err = s.roleSaver.AssignUserRole(ctx, userID, roleID)
	if err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			return fmt.Errorf("%s: %w", op, ErrUserAlreadyInRole)
		}
		log.Error("failed to assign user role", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user role assigned successfully")
	return nil
}

func (s *Service) RevokeRoleFromUser(ctx context.Context, userID, roleID int64) error {
	const op = "role.RevokeRoleFromUser"
	log := s.log.With(slog.String("op", op), slog.Int64("user_id", userID), slog.Int64("role_id", roleID))

	_, err := s.userProvider.UserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return fmt.Errorf("%s: user not found: %w", op, storage.ErrUserNotFound)
		}
		return fmt.Errorf("%s: failed to get user: %w", op, err)
	}

	_, err = s.roleProvider.RoleByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("%s: role not found: %w", op, ErrRoleNotFound)
		}
		return fmt.Errorf("%s: failed to get role: %w", op, err)
	}

	err = s.roleSaver.RevokeUserRole(ctx, userID, roleID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("%s: %w", op, ErrUserNotInRole)
		}
		log.Error("failed to revoke user role", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user role revoked successfully")
	return nil
}

func (s *Service) UserRoles(ctx context.Context, userID int64) ([]models.Role, error) {
	const op = "role.UserRoles"
	log := s.log.With(slog.String("op", op), slog.Int64("user_id", userID))

	_, err := s.userProvider.UserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("%s: user not found: %w", op, storage.ErrUserNotFound)
		}
		return nil, fmt.Errorf("%s: failed to get user: %w", op, err)
	}

	roles, err := s.roleProvider.UserRoles(ctx, userID)
	if err != nil {
		log.Error("failed to get user roles", slog.Any("error", err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("successfully retrieved user roles", slog.Int("count", len(roles)))
	return roles, nil
}

func (s *Service) RolePermissions(ctx context.Context, roleID int64) ([]models.Permission, error) {
	const op = "role.RolePermissions"
	log := s.log.With(slog.String("op", op), slog.Int64("role_id", roleID))

	_, err := s.roleProvider.RoleByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("%s: role not found: %w", op, ErrRoleNotFound)
		}
		return nil, fmt.Errorf("%s: failed to get role: %w", op, err)
	}

	rolePerms, err := s.roleProvider.RolePermissions(ctx, roleID)
	if err != nil {
		log.Error("failed to get user roles for permissions check", slog.Any("error", err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("successfully retrieved role permissions", slog.Int("count", len(rolePerms)))
	return rolePerms, nil
}

func (s *Service) AllRoles(ctx context.Context) ([]models.Role, error) {
	const op = "role.AllRoles"
	log := s.log.With(slog.String("op", op))

	roles, err := s.roleProvider.AllRoles(ctx)
	if err != nil {
		log.Error("failed to get all roles", slog.Any("error", err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("successfully retrieved all roles", slog.Int("count", len(roles)))
	return roles, nil
}
