package permission

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/radahn42/sso/internal/domain/models"
	"github.com/radahn42/sso/internal/storage"
)

var (
	ErrPermissionExists        = errors.New("permission already exists")
	ErrPermissionInUse         = errors.New("permission already in use")
	ErrPermissionAlreadyInRole = errors.New("permission already assigned to role")
	ErrPermissionNotInRole     = errors.New("permission not assigned to role")
	ErrPermissionNotFound      = errors.New("permission not found")
	ErrRoleNotFound            = errors.New("role not found")
)

type Saver interface {
	SavePermission(ctx context.Context, name, description string) (permissionID int64, err error)
	DeletePermission(ctx context.Context, permissionID int64) error
	UpdatePermission(ctx context.Context, permissionID int64, name, description string) error
	AddPermissionToRole(ctx context.Context, roleID, permissionID int64) error
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID int64) error
}

type Provider interface {
	PermissionByID(ctx context.Context, permissionID int64) (*models.Permission, error)
	PermissionByName(ctx context.Context, name string) (models.Permission, error)
	AllPermissions(ctx context.Context) ([]models.Permission, error)
	HasPermission(ctx context.Context, userID int64, permission string) (bool, error)
	UserPermissions(ctx context.Context, userID int64) ([]models.Permission, error)
}

type RoleSaver interface {
	RoleByName(ctx context.Context, name string) (models.Role, error)
	RoleByID(ctx context.Context, roleID int64) (models.Role, error)
}

type RoleProvider interface {
	RoleByName(ctx context.Context, name string) (models.Role, error)
	RoleByID(ctx context.Context, roleID int64) (models.Role, error)
	RolePermissions(ctx context.Context, roleID int64) ([]models.Permission, error)
	UserRoles(ctx context.Context, userID int64) ([]models.Role, error)
}

type UserProvider interface {
	UserByID(ctx context.Context, userID int64) (models.User, error)
}

type Service struct {
	log          *slog.Logger
	permSaver    Saver
	permProvider Provider
	roleSaver    RoleSaver
	roleProvider RoleProvider
	userProvider UserProvider
}

func New(
	log *slog.Logger,
	permSaver Saver,
	permProvider Provider,
	roleSaver RoleSaver,
	roleProvider RoleProvider,
	userProvider UserProvider,
) *Service {
	return &Service{
		log:          log,
		permSaver:    permSaver,
		permProvider: permProvider,
		roleSaver:    roleSaver,
		roleProvider: roleProvider,
		userProvider: userProvider,
	}
}

func (s *Service) CreatePermission(ctx context.Context, name, description string) (int64, error) {
	const op = "permission.CreatePermission"
	log := s.log.With(slog.String("op", op), slog.String("name", name))

	_, err := s.permProvider.PermissionByName(ctx, name)
	if err == nil {
		log.Warn("permission with this name already exists")
		return 0, fmt.Errorf("%s: %w", op, ErrPermissionExists)
	}
	if !errors.Is(err, storage.ErrNotFound) {
		log.Error("failed to check existing permission by name", slog.Any("error", err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	permissionID, err := s.permSaver.SavePermission(ctx, name, description)
	if err != nil {
		log.Error("failed to save permission", slog.Any("error", err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("permission created successfully", slog.Int64("permission_id", permissionID))
	return permissionID, nil
}

func (s *Service) DeletePermission(ctx context.Context, permissionID int64) error {
	const op = "permission.DeletePermission"
	log := slog.With(slog.String("op", op), slog.Int64("permission_id", permissionID))

	_, err := s.permProvider.PermissionByID(ctx, permissionID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			log.Warn("permission not found for deletion")
			return fmt.Errorf("%s: %w", op, ErrPermissionNotFound)
		}
		log.Error("failed to get permission by ID before deletion", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	err = s.permSaver.DeletePermission(ctx, permissionID)
	if err != nil {
		if errors.Is(err, storage.ErrForeignKeyViolation) {
			log.Warn("attempt to delete permission that is in use", slog.Int64("permission_id", permissionID))
			return fmt.Errorf("%s: %w", op, ErrPermissionInUse)
		}
		log.Error("failed to delete permission", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("permission deleted successfully")
	return nil
}

func (s *Service) UpdatePermission(ctx context.Context, permissionID int64, name, description string) error {
	const op = "permission.UpdatePermission"
	log := slog.With(slog.String("op", op), slog.Int64("permission_id", permissionID))

	existingPerm, err := s.permProvider.PermissionByID(ctx, permissionID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			log.Warn("permission not found for update")
			return fmt.Errorf("%s: %w", op, ErrPermissionNotFound)
		}
		log.Error("failed to get permission by ID", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	if name != "" && name != existingPerm.Name {
		_, err := s.permProvider.PermissionByName(ctx, name)
		if err == nil {
			log.Warn("new permission name already exists")
			return fmt.Errorf("%s: %w", op, ErrPermissionExists)
		}
		if !errors.Is(err, storage.ErrNotFound) {
			log.Error("failed to check new permission name for conflict", slog.Any("error", err))
			return fmt.Errorf("%s: %w", op, err)
		}
	}

	err = s.permSaver.UpdatePermission(ctx, permissionID, name, description)
	if err != nil {
		log.Error("failed to update permission", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("permission updated successfully")
	return nil
}

func (s *Service) PermissionByID(ctx context.Context, permissionID int64) (*models.Permission, error) {
	const op = "permission.PermissionByID"

	perm, err := s.permProvider.PermissionByID(ctx, permissionID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("%s: %w", op, ErrPermissionNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return perm, nil
}

func (s *Service) PermissionByName(ctx context.Context, name string) (*models.Permission, error) {
	const op = "permission.PermissionByName"

	perm, err := s.permProvider.PermissionByName(ctx, name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("%s: %w", op, ErrPermissionNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &perm, nil
}

func (s *Service) AllPermissions(ctx context.Context) ([]models.Permission, error) {
	const op = "permission.AllPermissions"

	perms, err := s.permProvider.AllPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return perms, nil
}

func (s *Service) AddPermissionToRole(ctx context.Context, roleID int64, permissionID int64) error {
	const op = "role.AddPermissionToRole"
	log := s.log.With(
		slog.String("op", op),
		slog.Int64("role_id", roleID),
		slog.Int64("permission_id", permissionID),
	)

	role, err := s.roleProvider.RoleByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			log.Warn("role not found for adding permission")
			return fmt.Errorf("%s: %w", op, ErrRoleNotFound)
		}
		log.Error("failed to get role by name", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	permission, err := s.permProvider.PermissionByID(ctx, permissionID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			log.Warn("permission not found to add to role")
			return fmt.Errorf("%s: %w", op, ErrPermissionNotFound)
		}
		log.Error("failed to get permission by name", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	err = s.permSaver.AddPermissionToRole(ctx, role.ID, permission.ID)
	if err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			log.Warn("permission already assigned to role")
			return fmt.Errorf("%s: %w", op, ErrPermissionAlreadyInRole)
		}
		log.Error("failed to add permission to role", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("permission added to role successfully")
	return nil
}

func (s *Service) RemovePermissionFromRole(ctx context.Context, roleID int64, permissionID int64) error {
	const op = "role.RemovePermissionFromRole"
	log := s.log.With(
		slog.String("op", op),
		slog.Int64("role_id", roleID),
		slog.Int64("permission_id", permissionID),
	)

	role, err := s.roleProvider.RoleByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			log.Warn("role not found for removing permission")
			return fmt.Errorf("%s: %w", op, ErrRoleNotFound)
		}
		log.Error("failed to get role by name", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	permission, err := s.permProvider.PermissionByID(ctx, permissionID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			log.Warn("permission not found to remove from role")
			return fmt.Errorf("%s: %w", op, ErrPermissionNotFound)
		}
		log.Error("failed to get permission by name", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	err = s.permSaver.RemovePermissionFromRole(ctx, role.ID, permission.ID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			log.Warn("permission not assigned to role for removal")
			return fmt.Errorf("%s: %w", op, ErrPermissionNotInRole)
		}
		log.Error("failed to remove permission from role", slog.Any("error", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("permission removed from role successfully")
	return nil
}

func (s *Service) HasPermission(ctx context.Context, userID int64, permission string) (bool, error) {
	return s.permProvider.HasPermission(ctx, userID, permission)
}

func (s *Service) UserPermissions(ctx context.Context, userID int64) ([]models.Permission, error) {
	const op = "role.UserPermissions"
	log := s.log.With(slog.String("op", op), slog.Int64("user_id", userID))

	_, err := s.userProvider.UserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("%s: user not found: %w", op, storage.ErrUserNotFound)
		}
		return nil, fmt.Errorf("%s: failed to get user: %w", op, err)
	}

	userRoles, err := s.roleProvider.UserRoles(ctx, userID)
	if err != nil {
		log.Error("failed to get user roles for permissions check", slog.Any("error", err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	uniquePermissions := make(map[int64]models.Permission)
	for _, role := range userRoles {
		rolePerms, err := s.roleProvider.RolePermissions(ctx, role.ID)
		if err != nil {
			log.Error("failed to get permissions for role", slog.Int64("role_id", role.ID))
			return nil, fmt.Errorf("%s: failed to get permissions for role %d: %w", op, role.ID, err)
		}
		for _, perm := range rolePerms {
			uniquePermissions[perm.ID] = perm
		}
	}

	result := make([]models.Permission, 0, len(uniquePermissions))
	for _, perm := range uniquePermissions {
		result = append(result, perm)
	}

	log.Info("successfully retrieved user permissions", slog.Int("count", len(result)))
	return result, nil
}
