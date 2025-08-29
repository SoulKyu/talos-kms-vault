package server

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/lightdiscord/talos-kms-vault/pkg/leaderelection"
	"github.com/siderolabs/kms-client/api/kms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// LeaderAwareServer wraps the KMS server with leader election capabilities
type LeaderAwareServer struct {
	kms.UnimplementedKMSServiceServer

	server             *Server
	electionController *leaderelection.ElectionController
	logger             *slog.Logger

	mu       sync.RWMutex
	isLeader bool
	isActive bool
}

// NewLeaderAwareServer creates a new leader-aware KMS server
func NewLeaderAwareServer(server *Server, electionController *leaderelection.ElectionController, logger *slog.Logger) *LeaderAwareServer {
	return &LeaderAwareServer{
		server:             server,
		electionController: electionController,
		logger:             logger,
		isLeader:           false,
		isActive:           false,
	}
}

// Start starts the leader election and server
func (las *LeaderAwareServer) Start(ctx context.Context) error {
	las.logger.Info("Starting leader-aware KMS server")

	// Start the election controller
	if err := las.electionController.Start(ctx); err != nil {
		return fmt.Errorf("failed to start leader election: %w", err)
	}

	return nil
}

// Stop stops the leader election and server
func (las *LeaderAwareServer) Stop() {
	las.logger.Info("Stopping leader-aware KMS server")

	las.mu.Lock()
	las.isActive = false
	las.isLeader = false
	las.mu.Unlock()

	las.electionController.Stop()
}

// OnBecomeLeader is called when this instance becomes the leader
func (las *LeaderAwareServer) OnBecomeLeader(ctx context.Context) {
	las.mu.Lock()
	las.isLeader = true
	las.isActive = true
	las.mu.Unlock()

	las.logger.Info("Became leader - KMS server is now active")
}

// OnLoseLeadership is called when this instance loses leadership
func (las *LeaderAwareServer) OnLoseLeadership() {
	las.mu.Lock()
	las.isLeader = false
	las.isActive = false
	las.mu.Unlock()

	las.logger.Info("Lost leadership - KMS server is now passive")
}

// OnLeaderChange is called when the leader changes
func (las *LeaderAwareServer) OnLeaderChange(leader string) {
	las.logger.Info("Leader changed", "currentLeader", leader)
}

// Seal implements the KMS Seal operation (leader-only)
func (las *LeaderAwareServer) Seal(ctx context.Context, request *kms.Request) (*kms.Response, error) {
	if !las.checkLeadership() {
		return nil, las.createNotLeaderError()
	}

	las.logger.Debug("Processing seal request as leader")
	return las.server.Seal(ctx, request)
}

// Unseal implements the KMS Unseal operation (leader-only)
func (las *LeaderAwareServer) Unseal(ctx context.Context, request *kms.Request) (*kms.Response, error) {
	if !las.checkLeadership() {
		return nil, las.createNotLeaderError()
	}

	las.logger.Debug("Processing unseal request as leader")
	return las.server.Unseal(ctx, request)
}

// IsReady returns whether this instance is ready to serve requests
func (las *LeaderAwareServer) IsReady() bool {
	las.mu.RLock()
	defer las.mu.RUnlock()

	return las.isActive
}

// checkLeadership verifies if this instance can process requests
func (las *LeaderAwareServer) checkLeadership() bool {
	las.mu.RLock()
	defer las.mu.RUnlock()

	return las.isLeader && las.isActive
}

// createNotLeaderError creates an appropriate error when not the leader
func (las *LeaderAwareServer) createNotLeaderError() error {
	currentLeader := las.electionController.GetCurrentLeader()

	if currentLeader == "" {
		return status.Error(codes.Unavailable, "No leader elected - service unavailable")
	}

	return status.Errorf(codes.Unavailable,
		"Not the leader - current leader is %s", currentLeader)
}

// GetLeadershipInfo returns information about the current leadership state
func (las *LeaderAwareServer) GetLeadershipInfo() LeadershipInfo {
	las.mu.RLock()
	defer las.mu.RUnlock()

	metrics := las.electionController.GetMetrics()

	return LeadershipInfo{
		IsLeader:          las.isLeader,
		IsActive:          las.isActive,
		CurrentLeader:     metrics.CurrentLeader,
		LeadershipChanges: metrics.LeadershipChanges,
		AcquisitionErrors: metrics.AcquisitionErrors,
		RenewalErrors:     metrics.RenewalErrors,
		LastLeaderChange:  metrics.LastLeaderChange,
	}
}

// LeadershipInfo contains information about the leadership state
type LeadershipInfo struct {
	IsLeader          bool      `json:"isLeader"`
	IsActive          bool      `json:"isActive"`
	CurrentLeader     string    `json:"currentLeader"`
	LeadershipChanges int64     `json:"leadershipChanges"`
	AcquisitionErrors int64     `json:"acquisitionErrors"`
	RenewalErrors     int64     `json:"renewalErrors"`
	LastLeaderChange  time.Time `json:"lastLeaderChange"`
}
