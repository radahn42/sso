package grpcapp

import (
	"fmt"
	"github.com/radahn42/sso/internal/config"
	"log/slog"
	"net"

	"github.com/radahn42/sso/internal/grpc/interceptor"

	"buf.build/go/protovalidate"
	protovalidate_middleware "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/protovalidate"
	authgrpc "github.com/radahn42/sso/internal/grpc/auth"
	"google.golang.org/grpc"
)

type App struct {
	log        *slog.Logger
	gRPCServer *grpc.Server
	host       string
	port       int
}

func New(
	log *slog.Logger,
	cfg *config.Config,
	authService authgrpc.Service,
	roleService authgrpc.RoleService,
	permService authgrpc.PermissionService,
	appProvider interceptor.AppProvider,
	permProvider interceptor.PermissionProvider,
	tokenProvider interceptor.TokenProvider,
) *App {
	validator, err := protovalidate.New()
	if err != nil {
		panic(err)
	}

	gRPCServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			interceptor.AuthInterceptor(log, appProvider, permProvider, tokenProvider, map[string][]string{
				"/auth.AuthService/ChangePassword": {"password:change"},
				"/auth.AuthService/Logout":         {}, // Просто валидный токен

				"/auth.AuthService/AssignRoleToUser":   {"user_roles:assign"},
				"/auth.AuthService/RevokeRoleFromUser": {"user_roles:revoke"},
				"/auth.AuthService/GetUserRoles":       {"user_roles:read"},

				"/auth.AuthService/GetAllRoles": {"roles:read"},
				"/auth.AuthService/CreateRole":  {"roles:create"},
				"/auth.AuthService/DeleteRole":  {"roles:delete"},
				"/auth.AuthService/UpdateRole":  {"roles:update"},
			}),
			protovalidate_middleware.UnaryServerInterceptor(validator),
		),
	)

	authgrpc.Register(gRPCServer, authService, roleService, permService)

	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       cfg.GRPC.Port,
		host:       cfg.GRPC.Host,
	}
}

// MustRun runs gRPC server and panics if any error occurs.
func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

// Run runs gRPC server.
func (a *App) Run() error {
	const op = "grpcapp.Run"

	log := a.log.With(
		slog.String("op", op),
		slog.Int("port", a.port),
	)

	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", a.host, a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("gRPC server is running", slog.String("addr", l.Addr().String()))

	if err := a.gRPCServer.Serve(l); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// Stop stops gRPC server.
func (a *App) Stop() {
	const op = "grpcapp.Stop"

	a.log.With(slog.String("op", op)).
		Info("stopping gRPC server")

	a.gRPCServer.GracefulStop()
}
