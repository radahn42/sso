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

type Auth interface {
	Login(ctx context.Context, email string, password string, appID int) (token string, err error)
	RegisterUser(ctx context.Context, email string, password string) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
	SetUserIsAdmin(ctx context.Context, email string) (userID int64, err error)
	SetUserIsNotAdmin(ctx context.Context, email string) (userID int64, err error)
	RequestPasswordReset(ctx context.Context, email string) error
	ConfirmPasswordReset(ctx context.Context, email, resetToken, newPassword string) error
	ChangePassword(ctx context.Context, userID int64, oldPassword, newPassword string) error
	Logout(ctx context.Context, token string) error
	ValidateToken(ctx context.Context, tokenString string) (claims *models.UserClaims, err error)
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	token, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword(), int(req.GetAppId()))
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Errorf(codes.InvalidArgument, "invalid credentials")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.LoginResponse{Token: token}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	userID, err := s.auth.RegisterUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			return nil, status.Errorf(codes.AlreadyExists, "user already exists")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.RegisterResponse{UserId: userID}, nil
}

func (s *serverAPI) RequestPasswordReset(ctx context.Context, req *ssov1.RequestPasswordResetRequest) (*ssov1.RequestPasswordResetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "RequestPasswordReset not implemented yet")
}

func (s *serverAPI) ConfirmPasswordReset(ctx context.Context, req *ssov1.ConfirmPasswordResetRequest) (*ssov1.ConfirmPasswordResetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "ConfirmPasswordReset not implemented yet")
}

func (s *serverAPI) ChangePassword(ctx context.Context, req *ssov1.ChangePasswordRequest) (*ssov1.ChangePasswordResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "ChangePassword not implemented yet")
}

func (s *serverAPI) Logout(ctx context.Context, req *ssov1.LogoutRequest) (*ssov1.LogoutResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "Logout not implemented yet")
}

func (s *serverAPI) AssignRoleToUser(ctx context.Context, req *ssov1.AssignRoleToUserRequest) (*ssov1.AssignRoleToUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "AssignRoleToUser not implemented yet")
}

func (s *serverAPI) RevokeRoleFromUser(ctx context.Context, req *ssov1.RevokeRoleFromUserRequest) (*ssov1.RevokeRoleFromUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "RevokeRoleFromUser not implemented yet")
}

func (s *serverAPI) GetUserRoles(ctx context.Context, req *ssov1.GetUserRolesRequest) (*ssov1.GetUserRolesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "GetUserRoles not implemented yet")
}

func (s *serverAPI) GetAllRoles(ctx context.Context, req *ssov1.GetAllRolesRequest) (*ssov1.GetAllRolesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "GetAllRoles not implemented yet")
}

func (s *serverAPI) CreateRole(ctx context.Context, req *ssov1.CreateRoleRequest) (*ssov1.CreateRoleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "CreateRole not implemented yet")
}

func (s *serverAPI) DeleteRole(ctx context.Context, req *ssov1.DeleteRoleRequest) (*ssov1.DeleteRoleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "DeleteRole not implemented yet")
}

func (s *serverAPI) UpdateRole(ctx context.Context, req *ssov1.UpdateRoleRequest) (*ssov1.UpdateRoleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "UpdateRole not implemented yet")
}

func (s *serverAPI) HasPermission(ctx context.Context, req *ssov1.HasPermissionRequest) (*ssov1.HasPermissionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "HasPermission not implemented yet")
}

func (s *serverAPI) GetUserPermissions(ctx context.Context, req *ssov1.GetUserPermissionsRequest) (*ssov1.GetUserPermissionsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "GetUserPermissions not implemented yet")
}

func (s *serverAPI) CreatePermission(ctx context.Context, req *ssov1.CreatePermissionRequest) (*ssov1.CreatePermissionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "CreatePermission not implemented yet")
}

func (s *serverAPI) DeletePermission(ctx context.Context, req *ssov1.DeletePermissionRequest) (*ssov1.DeletePermissionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "DeletePermission not implemented yet")
}

func (s *serverAPI) UpdatePermission(ctx context.Context, req *ssov1.UpdatePermissionRequest) (*ssov1.UpdatePermissionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "UpdatePermission not implemented yet")
}

func (s *serverAPI) GetPermissionByID(ctx context.Context, req *ssov1.GetPermissionByIDRequest) (*ssov1.GetPermissionByIDResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "GetPermissionByID not implemented yet")
}

func (s *serverAPI) GetPermissionByName(ctx context.Context, req *ssov1.GetPermissionByNameRequest) (*ssov1.GetPermissionByNameResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "GetPermissionByName not implemented yet")
}

func (s *serverAPI) GetAllPermissions(ctx context.Context, req *ssov1.GetAllPermissionsRequest) (*ssov1.GetAllPermissionsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "GetAllPermissions not implemented yet")
}

func (s *serverAPI) AddPermissionToRole(ctx context.Context, req *ssov1.AddPermissionToRoleRequest) (*ssov1.AddPermissionToRoleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "AddPermissionToRole not implemented yet")
}

func (s *serverAPI) RemovePermissionFromRole(ctx context.Context, req *ssov1.RemovePermissionFromRoleRequest) (*ssov1.RemovePermissionFromRoleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "RemovePermissionFromRole not implemented yet")
}

func (s *serverAPI) GetRolePermissions(ctx context.Context, req *ssov1.GetRolePermissionsRequest) (*ssov1.GetRolePermissionsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "GetRolePermissions not implemented yet")
}
