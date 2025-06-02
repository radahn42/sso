package auth

import (
	"context"
	"errors"

	ssov1 "github.com/radahn42/protos/gen/proto/sso"
	"github.com/radahn42/sso/internal/domain/models"
	"github.com/radahn42/sso/internal/services/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Service Объединяет аутентификацию и управление паролями
type Service interface {
	RegisterUser(ctx context.Context, email string, password string) (userID int64, err error)
	Login(ctx context.Context, email string, password string, appID int) (token string, err error)
	Logout(ctx context.Context, token string) error
	RequestPasswordReset(ctx context.Context, email string) error
	ConfirmPasswordReset(ctx context.Context, email, resetToken, newPassword string) error
	ChangePassword(ctx context.Context, userID int64, oldPassword, newPassword string) error
	ValidateToken(ctx context.Context, tokenString string) (*models.UserClaims, error)
}

// RoleService Интерфейс для управления ролями
type RoleService interface {
	AssignRoleToUser(ctx context.Context, userID, roleID int64) error
	RevokeRoleFromUser(ctx context.Context, userID, roleID int64) error
	UserRoles(ctx context.Context, userID int64) ([]models.Role, error)
	AllRoles(ctx context.Context) ([]models.Role, error)
	CreateRole(ctx context.Context, name, description string) (roleID int64, err error)
	DeleteRole(ctx context.Context, roleID int64) error
	UpdateRole(ctx context.Context, roleID int64, name, description string) error
	RolePermissions(ctx context.Context, roleID int64) ([]models.Permission, error) // Возможно, этот метод здесь
}

// PermissionService Интерфейс для управления разрешениями
type PermissionService interface {
	HasPermission(ctx context.Context, userID int64, permission string) (bool, error)
	UserPermissions(ctx context.Context, userID int64) ([]models.Permission, error)
	CreatePermission(ctx context.Context, name, description string) (permissionID int64, err error)
	DeletePermission(ctx context.Context, id int64) error
	UpdatePermission(ctx context.Context, id int64, name, description string) error
	PermissionByID(ctx context.Context, id int64) (*models.Permission, error)
	PermissionByName(ctx context.Context, name string) (*models.Permission, error)
	AllPermissions(ctx context.Context) ([]models.Permission, error)
	AddPermissionToRole(ctx context.Context, roleID, permissionID int64) error
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID int64) error
}
type serverAPI struct {
	ssov1.UnimplementedAuthServiceServer
	authService Service
	roleService RoleService
	permService PermissionService
}

func Register(gRPC *grpc.Server, authService Service, roleService RoleService, permService PermissionService) {
	ssov1.RegisterAuthServiceServer(gRPC, &serverAPI{
		authService: authService,
		roleService: roleService,
		permService: permService,
	})
}

func (s *serverAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	token, err := s.authService.Login(ctx, req.GetEmail(), req.GetPassword(), int(req.GetAppId()))
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Errorf(codes.InvalidArgument, "invalid credentials")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.LoginResponse{Token: token}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	userID, err := s.authService.RegisterUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			return nil, status.Errorf(codes.AlreadyExists, "user already exists")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.RegisterResponse{UserId: userID}, nil
}

func (s *serverAPI) RequestPasswordReset(ctx context.Context, req *ssov1.RequestPasswordResetRequest) (*ssov1.RequestPasswordResetResponse, error) {
	err := s.authService.RequestPasswordReset(ctx, req.GetEmail())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to request password reset") // TODO: Добавить специфичную обработку ошибок
	}
	return &ssov1.RequestPasswordResetResponse{}, nil
}

func (s *serverAPI) ConfirmPasswordReset(ctx context.Context, req *ssov1.ConfirmPasswordResetRequest) (*ssov1.ConfirmPasswordResetResponse, error) {
	err := s.authService.ConfirmPasswordReset(ctx, req.GetEmail(), req.GetResetToken(), req.GetNewPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to confirm password reset") // TODO: Добавить специфичную обработку ошибок
	}
	return &ssov1.ConfirmPasswordResetResponse{}, nil
}

func (s *serverAPI) ChangePassword(ctx context.Context, req *ssov1.ChangePasswordRequest) (*ssov1.ChangePasswordResponse, error) {
	userID, ok := ctx.Value("userID").(int64) // TODO: Сейчас id не пробрасывается в ctx, добавить это в будущем
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "user not authenticated or ID not found in context")
	}

	err := s.authService.ChangePassword(ctx, userID, req.GetOldPassword(), req.GetNewPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to change password") // TODO: Добавить специфичную обработку ошибок
	}
	return &ssov1.ChangePasswordResponse{}, nil
}

func (s *serverAPI) Logout(ctx context.Context, req *ssov1.LogoutRequest) (*ssov1.LogoutResponse, error) {
	err := s.authService.Logout(ctx, req.GetToken())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to logout") // TODO: Добавить специфичную обработку ошибок
	}
	return &ssov1.LogoutResponse{}, nil
}

func (s *serverAPI) AssignRoleToUser(ctx context.Context, req *ssov1.AssignRoleToUserRequest) (*ssov1.AssignRoleToUserResponse, error) {
	err := s.roleService.AssignRoleToUser(ctx, req.GetUserId(), req.GetRoleId())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to assign role to user") // TODO: Добавить специфичную обработку ошибок
	}
	return &ssov1.AssignRoleToUserResponse{}, nil
}

func (s *serverAPI) RevokeRoleFromUser(ctx context.Context, req *ssov1.RevokeRoleFromUserRequest) (*ssov1.RevokeRoleFromUserResponse, error) {
	err := s.roleService.RevokeRoleFromUser(ctx, req.GetUserId(), req.GetRoleId())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to revoke role from user") // TODO: Добавить специфичную обработку ошибок
	}
	return &ssov1.RevokeRoleFromUserResponse{}, nil
}

func (s *serverAPI) GetUserRoles(ctx context.Context, req *ssov1.GetUserRolesRequest) (*ssov1.GetUserRolesResponse, error) {
	userID := req.GetUserId()
	roles, err := s.roleService.UserRoles(ctx, userID)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get user roles") // TODO: Добавить специфичную обработку ошибок
	}

	ssoRoles := make([]*ssov1.Role, len(roles))
	for i, r := range roles {
		ssoRoles[i] = &ssov1.Role{
			Id:          r.ID,
			Name:        r.Name,
			Description: r.Description,
		}
	}
	return &ssov1.GetUserRolesResponse{Roles: ssoRoles}, nil
}

func (s *serverAPI) GetAllRoles(ctx context.Context, req *ssov1.GetAllRolesRequest) (*ssov1.GetAllRolesResponse, error) {
	roles, err := s.roleService.AllRoles(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get all roles") // TODO: Добавить специфичную обработку ошибок
	}

	ssoRoles := make([]*ssov1.Role, len(roles))
	for i, r := range roles {
		ssoRoles[i] = &ssov1.Role{
			Id:          r.ID,
			Name:        r.Name,
			Description: r.Description,
		}
	}
	return &ssov1.GetAllRolesResponse{Roles: ssoRoles}, nil
}

func (s *serverAPI) CreateRole(ctx context.Context, req *ssov1.CreateRoleRequest) (*ssov1.CreateRoleResponse, error) {
	roleID, err := s.roleService.CreateRole(ctx, req.GetName(), req.GetDescription())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create role: %v", err) // TODO: Добавить специфичную обработку ошибок
	}
	return &ssov1.CreateRoleResponse{RoleId: roleID}, nil
}

func (s *serverAPI) DeleteRole(ctx context.Context, req *ssov1.DeleteRoleRequest) (*ssov1.DeleteRoleResponse, error) {
	err := s.roleService.DeleteRole(ctx, req.GetRoleId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete role: %v", err) // TODO: Добавить специфичную обработку ошибок
	}
	return &ssov1.DeleteRoleResponse{}, nil
}

func (s *serverAPI) UpdateRole(ctx context.Context, req *ssov1.UpdateRoleRequest) (*ssov1.UpdateRoleResponse, error) {
	err := s.roleService.UpdateRole(ctx, req.GetRoleId(), req.GetName(), req.GetDescription())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to update role") // TODO: Добавить специфичную обработку ошибок
	}
	return &ssov1.UpdateRoleResponse{}, nil
}

func (s *serverAPI) HasPermission(ctx context.Context, req *ssov1.HasPermissionRequest) (*ssov1.HasPermissionResponse, error) {
	hasPerm, err := s.permService.HasPermission(ctx, req.GetUserId(), req.GetPermissionName())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to check permission") // TODO: Добавить специфичную обработку ошибок
	}
	return &ssov1.HasPermissionResponse{HasPermission: hasPerm}, nil
}

func (s *serverAPI) GetUserPermissions(ctx context.Context, req *ssov1.GetUserPermissionsRequest) (*ssov1.GetUserPermissionsResponse, error) {
	perms, err := s.permService.UserPermissions(ctx, req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get user permissions") // TODO: Добавить специфичную обработку ошибок
	}

	ssoPerms := make([]*ssov1.Permission, len(perms))
	for i, p := range perms {
		ssoPerms[i] = &ssov1.Permission{
			Id:          p.ID,
			Name:        p.Name,
			Description: p.Description,
		}
	}
	return &ssov1.GetUserPermissionsResponse{Permissions: ssoPerms}, nil
}

func (s *serverAPI) CreatePermission(ctx context.Context, req *ssov1.CreatePermissionRequest) (*ssov1.CreatePermissionResponse, error) {
	permID, err := s.permService.CreatePermission(ctx, req.GetName(), req.GetDescription())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to create permission") // TODO: Добавить специфичную обработку ошибок
	}
	return &ssov1.CreatePermissionResponse{PermissionId: permID}, nil
}

func (s *serverAPI) DeletePermission(ctx context.Context, req *ssov1.DeletePermissionRequest) (*ssov1.DeletePermissionResponse, error) {
	err := s.permService.DeletePermission(ctx, req.GetPermissionId())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to delete permission") // TODO: Добавить специфичную обработку ошибок
	}
	return &ssov1.DeletePermissionResponse{}, nil
}

func (s *serverAPI) UpdatePermission(ctx context.Context, req *ssov1.UpdatePermissionRequest) (*ssov1.UpdatePermissionResponse, error) {
	err := s.permService.UpdatePermission(ctx, req.GetPermissionId(), req.GetName(), req.GetDescription())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to update permission") // TODO: Добавить специфичную обработку ошибок
	}
	return &ssov1.UpdatePermissionResponse{}, nil
}

func (s *serverAPI) GetPermissionByID(ctx context.Context, req *ssov1.GetPermissionByIDRequest) (*ssov1.GetPermissionByIDResponse, error) {
	perm, err := s.permService.PermissionByID(ctx, req.GetPermissionId())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get permission by ID") // TODO: Добавить специфичную обработку ошибок
	}
	if perm == nil {
		return nil, status.Errorf(codes.NotFound, "permission with ID %d not found", req.GetPermissionId())
	}
	return &ssov1.GetPermissionByIDResponse{
		Permission: &ssov1.Permission{
			Id:          perm.ID,
			Name:        perm.Name,
			Description: perm.Description,
		},
	}, nil
}

func (s *serverAPI) GetPermissionByName(ctx context.Context, req *ssov1.GetPermissionByNameRequest) (*ssov1.GetPermissionByNameResponse, error) {
	perm, err := s.permService.PermissionByName(ctx, req.GetName())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get permission by name") // TODO: Добавить специфичную обработку ошибок
	}
	if perm == nil {
		return nil, status.Errorf(codes.NotFound, "permission with name '%s' not found", req.GetName())
	}
	return &ssov1.GetPermissionByNameResponse{
		Permission: &ssov1.Permission{
			Id:          perm.ID,
			Name:        perm.Name,
			Description: perm.Description,
		},
	}, nil
}

func (s *serverAPI) GetAllPermissions(ctx context.Context, req *ssov1.GetAllPermissionsRequest) (*ssov1.GetAllPermissionsResponse, error) {
	perms, err := s.permService.AllPermissions(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get all permissions") // TODO: Добавить специфичную обработку ошибок
	}
	ssoPerms := make([]*ssov1.Permission, len(perms))
	for i, p := range perms {
		ssoPerms[i] = &ssov1.Permission{
			Id:          p.ID,
			Name:        p.Name,
			Description: p.Description,
		}
	}
	return &ssov1.GetAllPermissionsResponse{Permissions: ssoPerms}, nil
}

func (s *serverAPI) AddPermissionToRole(ctx context.Context, req *ssov1.AddPermissionToRoleRequest) (*ssov1.AddPermissionToRoleResponse, error) {
	err := s.permService.AddPermissionToRole(ctx, req.GetRoleId(), req.GetPermissionId())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to add permission to role") // TODO: Добавить специфичную обработку ошибок
	}
	return &ssov1.AddPermissionToRoleResponse{}, nil
}

func (s *serverAPI) RemovePermissionFromRole(ctx context.Context, req *ssov1.RemovePermissionFromRoleRequest) (*ssov1.RemovePermissionFromRoleResponse, error) {
	err := s.permService.RemovePermissionFromRole(ctx, req.GetRoleId(), req.GetPermissionId())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to remove permission from role") // TODO: Добавить специфичную обработку ошибок
	}
	return &ssov1.RemovePermissionFromRoleResponse{}, nil
}

func (s *serverAPI) GetRolePermissions(ctx context.Context, req *ssov1.GetRolePermissionsRequest) (*ssov1.GetRolePermissionsResponse, error) {
	perms, err := s.roleService.RolePermissions(ctx, req.GetRoleId())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get role permissions") // TODO: Добавить специфичную обработку ошибок
	}
	ssoPerms := make([]*ssov1.Permission, len(perms))
	for i, p := range perms {
		ssoPerms[i] = &ssov1.Permission{
			Id:          p.ID,
			Name:        p.Name,
			Description: p.Description,
		}
	}
	return &ssov1.GetRolePermissionsResponse{Permissions: ssoPerms}, nil
}

func (s *serverAPI) ValidateToken(ctx context.Context, req *ssov1.ValidateTokenRequest) (*ssov1.ValidateTokenResponse, error) {
	claims, err := s.authService.ValidateToken(ctx, req.GetToken())
	if err != nil {
		if errors.Is(err, auth.ErrInvalidToken) {
			return nil, status.Errorf(codes.Unauthenticated, "invalid token")
		}
		return nil, status.Error(codes.Internal, "failed to validate token") // TODO: Добавить специфичную обработку ошибок
	}
	if claims == nil {
		return nil, status.Errorf(codes.Unauthenticated, "token validation failed: no claims")
	}

	return &ssov1.ValidateTokenResponse{
		UserId: claims.UserID,
		Email:  claims.Email,
		Roles:  claims.Roles,
	}, nil
}
