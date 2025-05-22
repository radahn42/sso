package suite

import (
	"context"
	ssov1 "github.com/radahn42/protos/gen/proto/sso"
	"github.com/radahn42/sso/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net"
	"strconv"
	"testing"
)

type Suite struct {
	*testing.T
	Cfg        *config.Config
	AuthClient ssov1.AuthClient
}

func New(t *testing.T) (context.Context, *Suite) {
	t.Helper()

	cfg := config.MustLoadByPath("../config/local_tests.yaml")

	ctx, cancel := context.WithTimeout(context.Background(), cfg.GRPC.Timeout)

	t.Cleanup(func() {
		t.Helper()
		cancel()
	})

	conn, err := grpc.DialContext(
		ctx,
		grpcAddress(cfg),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc server connection failed: %v", err)
	}

	client := ssov1.NewAuthClient(conn)

	return ctx, &Suite{
		T:          t,
		Cfg:        cfg,
		AuthClient: client,
	}
}

func grpcAddress(cfg *config.Config) string {
	return net.JoinHostPort(cfg.GRPC.Host, strconv.Itoa(cfg.GRPC.Port))
}
