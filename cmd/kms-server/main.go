package main

import (
	"context"
	"errors"
	"flag"
	"time"
	"github.com/lightdiscord/talos-kms-vault/pkg/auth"
	"github.com/lightdiscord/talos-kms-vault/pkg/server"
	"github.com/siderolabs/kms-client/api/kms"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"log/slog"
	"net"
	"os"
	"os/signal"
)

var kmsFlags struct {
	apiEndpoint string
	mountPath   string
}

func main() {
	flag.StringVar(&kmsFlags.apiEndpoint, "kms-api-endpoint", ":8080", "gRPC API endpoint for the KMS")
	flag.StringVar(&kmsFlags.mountPath, "mount-path", "transit", "Mount path for the Transit secret engine")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := run(ctx, logger); err != nil {
		logger.Error("Error during initialization", err)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	// Create authentication configuration from environment
	authConfig := auth.NewAuthConfigFromEnvironment()
	
	// Validate configuration
	if err := auth.ValidateConfig(authConfig); err != nil {
		return err
	}
	
	logger.Info("Initializing authentication", "method", authConfig.Method)
	
	// Create authentication manager
	authManager, err := auth.NewManager(authConfig, logger)
	if err != nil {
		return err
	}
	
	// Start authentication and token renewal
	if err := authManager.Start(ctx); err != nil {
		return err
	}
	
	// Ensure we clean up authentication on exit
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		if err := authManager.Stop(shutdownCtx); err != nil {
			logger.Error("Failed to stop auth manager", "error", err)
		}
	}()
	
	// Get authenticated Vault client
	client, err := authManager.GetClient()
	if err != nil {
		return err
	}
	
	srv := server.NewServer(client, logger, kmsFlags.mountPath)

	grpcSrv := grpc.NewServer()

	kms.RegisterKMSServiceServer(grpcSrv, srv)

	lis, err := net.Listen("tcp", kmsFlags.apiEndpoint)
	if err != nil {
		return err
	}

	logger.Info("Starting server", "endpoint", kmsFlags.apiEndpoint, "mount-path", kmsFlags.mountPath)

	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		return grpcSrv.Serve(lis)
	})

	eg.Go(func() error {
		<-ctx.Done()

		grpcSrv.Stop()

		return nil
	})

	if err := eg.Wait(); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}

	return nil
}
