package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/siderolabs/kms-client/api/kms"
	"github.com/soulkyu/talos-kms-vault/pkg/auth"
	"github.com/soulkyu/talos-kms-vault/pkg/leaderelection"
	"github.com/soulkyu/talos-kms-vault/pkg/server"
	"github.com/soulkyu/talos-kms-vault/pkg/validation"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var kmsFlags struct {
	apiEndpoint       string
	mountPath         string
	disableValidation bool
	allowUUIDVersions string
	disableEntropy    bool
	enableTLS         bool
	tlsCertFile       string
	tlsKeyFile        string

	// Leader election flags
	enableLeaderElection        bool
	leaderElectionNamespace     string
	leaderElectionName          string
	leaderElectionLeaseDuration time.Duration
	leaderElectionRenewDeadline time.Duration
	leaderElectionRetryPeriod   time.Duration
}

func main() {
	flag.StringVar(&kmsFlags.apiEndpoint, "kms-api-endpoint", ":8080", "gRPC API endpoint for the KMS")
	flag.StringVar(&kmsFlags.mountPath, "mount-path", "transit", "Mount path for the Transit secret engine")
	flag.BoolVar(&kmsFlags.disableValidation, "disable-validation", false, "Disable UUID validation (NOT recommended for production)")
	flag.StringVar(&kmsFlags.allowUUIDVersions, "allow-uuid-versions", "v4", "Allowed UUID versions (v4, v1-v5, or any)")
	flag.BoolVar(&kmsFlags.disableEntropy, "disable-entropy-check", false, "Disable entropy checking for UUIDs")
	flag.BoolVar(&kmsFlags.enableTLS, "enable-tls", false, "Enable TLS/HTTPS for gRPC server")
	flag.StringVar(&kmsFlags.tlsCertFile, "tls-cert", "server.crt", "Path to TLS certificate file")
	flag.StringVar(&kmsFlags.tlsKeyFile, "tls-key", "server.key", "Path to TLS private key file")

	// Leader election flags
	flag.BoolVar(&kmsFlags.enableLeaderElection, "enable-leader-election", false, "Enable leader election for multi-instance deployments")
	flag.StringVar(&kmsFlags.leaderElectionNamespace, "leader-election-namespace", leaderelection.GetNamespaceFromEnv(), "Kubernetes namespace for leader election")
	flag.StringVar(&kmsFlags.leaderElectionName, "leader-election-name", leaderelection.GetLeaseNameFromEnv(), "Name of the leader election lease")
	flag.DurationVar(&kmsFlags.leaderElectionLeaseDuration, "leader-election-lease-duration", 15*time.Second, "Duration of the leader election lease")
	flag.DurationVar(&kmsFlags.leaderElectionRenewDeadline, "leader-election-renew-deadline", 10*time.Second, "Deadline for renewing the leadership lease")
	flag.DurationVar(&kmsFlags.leaderElectionRetryPeriod, "leader-election-retry-period", 2*time.Second, "Retry period for leadership acquisition")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := run(ctx, logger); err != nil {
		logger.Error("Error during initialization", "error", err)
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

	// Create validation middleware based on flags
	validationConfig := createValidationConfig()
	validationMiddleware := validation.NewValidationMiddlewareFromConfig(validationConfig, logger)

	if !validationConfig.Enabled {
		logger.Warn("UUID validation is DISABLED - this is not recommended for production")
	}

	// Determine which server to use (leader-aware or regular)
	var kmsServer kms.KMSServiceServer
	var leaderAwareServer *server.LeaderAwareServer

	if kmsFlags.enableLeaderElection {
		// Create leader election configuration
		leaseConfig := createLeaderElectionConfig(logger)

		// Create election controller with callbacks
		callbackBuilder := leaderelection.NewCallbackBuilder(logger)
		electionController, err := leaderelection.NewElectionController(leaseConfig,
			leaderelection.LeaderElectionCallbacks{}, logger)
		if err != nil {
			return fmt.Errorf("failed to create election controller: %w", err)
		}

		// Create leader-aware server
		leaderAwareServer = server.NewLeaderAwareServer(srv, electionController, logger)

		// Set up callbacks
		callbacks := callbackBuilder.BuildGracefulShutdownCallbacks(
			leaderAwareServer.OnBecomeLeader,
			leaderAwareServer.OnLoseLeadership,
			5*time.Second,
		)
		callbacks.OnNewLeader = leaderAwareServer.OnLeaderChange

		// Update election controller with callbacks
		electionController, err = leaderelection.NewElectionController(leaseConfig, callbacks, logger)
		if err != nil {
			return fmt.Errorf("failed to create election controller with callbacks: %w", err)
		}

		// Start leader election
		if err := electionController.Start(ctx); err != nil {
			return fmt.Errorf("failed to start leader election: %w", err)
		}

		defer electionController.Stop()

		kmsServer = leaderAwareServer
		logger.Info("Leader election enabled", "identity", leaseConfig.Identity)
	} else {
		kmsServer = srv
		logger.Info("Running in single-instance mode (no leader election)")
	}

	// Create gRPC server with validation middleware
	var grpcOptions []grpc.ServerOption
	if validationMiddleware != nil {
		grpcOptions = append(grpcOptions,
			grpc.UnaryInterceptor(validationMiddleware.UnaryServerInterceptor()))
	}

	// Add TLS credentials if enabled
	if kmsFlags.enableTLS {
		cert, err := tls.LoadX509KeyPair(kmsFlags.tlsCertFile, kmsFlags.tlsKeyFile)
		if err != nil {
			logger.Error("Failed to load TLS certificate", "error", err)
			return err
		}

		creds := credentials.NewServerTLSFromCert(&cert)
		grpcOptions = append(grpcOptions, grpc.Creds(creds))

		logger.Info("TLS enabled", "cert", kmsFlags.tlsCertFile, "key", kmsFlags.tlsKeyFile)
	}

	grpcSrv := grpc.NewServer(grpcOptions...)

	kms.RegisterKMSServiceServer(grpcSrv, kmsServer)

	lis, err := net.Listen("tcp", kmsFlags.apiEndpoint)
	if err != nil {
		return err
	}

	protocol := "HTTP"
	if kmsFlags.enableTLS {
		protocol = "HTTPS"
	}

	logger.Info("Starting server",
		"protocol", protocol,
		"endpoint", kmsFlags.apiEndpoint,
		"mount-path", kmsFlags.mountPath)

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

// createValidationConfig creates validation config from command line flags and environment
func createValidationConfig() *validation.ValidationConfig {
	config := validation.DefaultValidationConfig()

	// Override with flags
	if kmsFlags.disableValidation {
		config.Enabled = false
		return config
	}

	// Handle UUID version requirements
	switch kmsFlags.allowUUIDVersions {
	case "v4":
		config.RequireUUIDv4 = true
	case "v1-v5", "any":
		config.RequireUUIDv4 = false
	default:
		// Default to v4 for security
		config.RequireUUIDv4 = true
	}

	// Entropy checking
	config.CheckEntropy = !kmsFlags.disableEntropy

	// Environment variable overrides
	if disableValidation := os.Getenv("KMS_DISABLE_VALIDATION"); disableValidation == "true" {
		config.Enabled = false
	}

	if disableEntropy := os.Getenv("KMS_DISABLE_ENTROPY_CHECK"); disableEntropy == "true" {
		config.CheckEntropy = false
	}

	if uuidVersions := os.Getenv("KMS_ALLOW_UUID_VERSIONS"); uuidVersions != "" {
		switch uuidVersions {
		case "v4":
			config.RequireUUIDv4 = true
		case "v1-v5", "any":
			config.RequireUUIDv4 = false
		}
	}

	return config
}

// createLeaderElectionConfig creates leader election config from command line flags
func createLeaderElectionConfig(logger *slog.Logger) *leaderelection.LeaseConfig {
	config := leaderelection.DefaultLeaseConfig()

	// Use command line flags
	config.Name = kmsFlags.leaderElectionName
	config.Namespace = kmsFlags.leaderElectionNamespace
	config.LeaseDuration = kmsFlags.leaderElectionLeaseDuration
	config.RenewDeadline = kmsFlags.leaderElectionRenewDeadline
	config.RetryPeriod = kmsFlags.leaderElectionRetryPeriod

	// Set identity from environment or defaults
	config.Identity = leaderelection.DefaultIdentity()

	logger.Info("Leader election configuration",
		"name", config.Name,
		"namespace", config.Namespace,
		"identity", config.Identity,
		"leaseDuration", config.LeaseDuration,
		"renewDeadline", config.RenewDeadline,
		"retryPeriod", config.RetryPeriod)

	return config
}
