package permission

import (
	"context"
	"errors"
	"fmt"
	"github.com/radahn42/sso/internal/domain/models"
	"github.com/radahn42/sso/internal/storage"
	"log/slog"
)

var (
	ErrPermissionExists   = errors.New("permission already exists")
	ErrPermissionNotFound = errors.New("permission not found")
)

type Saver interface {
	SavePermission(ctx context.Context, name, description string) (permissionID int64, err error)
	DeletePermission(ctx context.Context, permissionID int64) error
	UpdatePermission(ctx context.Context, permissionID int64, name, description string) error
}

type Provider interface {
	PermissionByID(ctx context.Context, permissionID int64) (models.Permission, error)
	PermissionByName(ctx context.Context, name string) (models.Permission, error)
	AllPermissions(ctx context.Context) ([]models.Permission, error)
}

type Service struct {
	log          *slog.Logger
	permSaver    Saver
	permProvider Provider
}

func New(
	log *slog.Logger,
	permSaver Saver,
	permProvider Provider,
) *Service {
	return &Service{
		log:          log,
		permSaver:    permSaver,
		permProvider: permProvider,
	}
}

func (s *Service) CreatePermission(ctx context.Context, name, description string) (int64, error) {
	const op = "permission.CreatePermission"
	log := s.log.With(slog.String("op", op), slog.String("name", name))

	_, err := s.permProvider.PermissionByName(ctx, name)
	if err != nil {
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
		//TODO: add storage.ErrForeignKeyViolation check
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

func (s *Service) PermissionByID(ctx context.Context, permissionID int64) (models.Permission, error) {
	const op = "permission.PermissionByID"

	perm, err := s.permProvider.PermissionByID(ctx, permissionID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return models.Permission{}, fmt.Errorf("%s: %w", op, ErrPermissionNotFound)
		}
		return models.Permission{}, fmt.Errorf("%s: %w", op, err)
	}
	return perm, nil
}

func (s *Service) PermissionByName(ctx context.Context, name string) (models.Permission, error) {
	const op = "permission.PermissionByID"

	perm, err := s.permProvider.PermissionByName(ctx, name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return models.Permission{}, fmt.Errorf("%s: %w", op, ErrPermissionNotFound)
		}
		return models.Permission{}, fmt.Errorf("%s: %w", op, err)
	}
	return perm, nil
}

func (s *Service) AllPermissions(ctx context.Context) ([]models.Permission, error) {
	const op = "permission.PermissionByID"

	perms, err := s.permProvider.AllPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return perms, nil
}
