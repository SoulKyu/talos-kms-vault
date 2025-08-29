package leaderelection

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// LeaderElectionCallbacks define the callbacks for leader election events
type LeaderElectionCallbacks struct {
	// OnStartedLeading is called when this instance becomes the leader
	OnStartedLeading func(ctx context.Context)
	// OnStoppedLeading is called when this instance stops being the leader
	OnStoppedLeading func()
	// OnNewLeader is called when a new leader is elected (including self)
	OnNewLeader func(identity string)
}

// ElectionController manages the leader election process
type ElectionController struct {
	config      *LeaseConfig
	leaseManager *LeaseManager
	callbacks   LeaderElectionCallbacks
	logger      *slog.Logger

	// Internal state
	mu               sync.RWMutex
	isLeader         bool
	isRunning        bool
	currentLeader    string
	lastLeaderChange time.Time
	
	// Control channels
	stopCh   chan struct{}
	stoppedCh chan struct{}
	
	// Metrics
	leadershipChanges int64
	acquisitionErrors int64
	renewalErrors    int64
}

// NewElectionController creates a new leader election controller
func NewElectionController(config *LeaseConfig, callbacks LeaderElectionCallbacks, logger *slog.Logger) (*ElectionController, error) {
	leaseManager, err := NewLeaseManager(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create lease manager: %w", err)
	}

	return &ElectionController{
		config:       config,
		leaseManager: leaseManager,
		callbacks:    callbacks,
		logger:       logger,
		stopCh:       make(chan struct{}),
		stoppedCh:    make(chan struct{}),
	}, nil
}

// Start begins the leader election process
func (ec *ElectionController) Start(ctx context.Context) error {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	
	if ec.isRunning {
		return fmt.Errorf("election controller is already running")
	}
	
	ec.isRunning = true
	ec.logger.Info("Starting leader election", 
		"identity", ec.config.Identity,
		"lease", ec.config.Name,
		"namespace", ec.config.Namespace)
	
	go ec.run(ctx)
	return nil
}

// Stop stops the leader election process
func (ec *ElectionController) Stop() {
	ec.mu.Lock()
	wasRunning := ec.isRunning
	ec.isRunning = false
	ec.mu.Unlock()
	
	if !wasRunning {
		return
	}
	
	ec.logger.Info("Stopping leader election", "identity", ec.config.Identity)
	close(ec.stopCh)
	<-ec.stoppedCh
}

// IsLeader returns whether this instance is currently the leader
func (ec *ElectionController) IsLeader() bool {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	return ec.isLeader
}

// GetCurrentLeader returns the identity of the current leader
func (ec *ElectionController) GetCurrentLeader() string {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	return ec.currentLeader
}

// GetMetrics returns leadership metrics
func (ec *ElectionController) GetMetrics() ElectionMetrics {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	
	return ElectionMetrics{
		IsLeader:          ec.isLeader,
		CurrentLeader:     ec.currentLeader,
		LeadershipChanges: ec.leadershipChanges,
		AcquisitionErrors: ec.acquisitionErrors,
		RenewalErrors:    ec.renewalErrors,
		LastLeaderChange:  ec.lastLeaderChange,
	}
}

// run is the main election loop
func (ec *ElectionController) run(ctx context.Context) {
	defer close(ec.stoppedCh)
	defer ec.releaseLeadershipOnExit(ctx)
	
	ticker := time.NewTicker(ec.config.RetryPeriod)
	defer ticker.Stop()
	
	// Try to acquire leadership immediately
	ec.tryAcquireLease(ctx)
	
	for {
		select {
		case <-ctx.Done():
			ec.logger.Info("Election context cancelled", "identity", ec.config.Identity)
			return
		case <-ec.stopCh:
			ec.logger.Info("Election stop requested", "identity", ec.config.Identity)
			return
		case <-ticker.C:
			ec.tryAcquireLease(ctx)
		}
	}
}

// tryAcquireLease attempts to acquire or renew the lease
func (ec *ElectionController) tryAcquireLease(ctx context.Context) {
	acquired, err := ec.leaseManager.AcquireLease(ctx)
	
	if err != nil {
		ec.mu.Lock()
		if ec.isLeader {
			ec.acquisitionErrors++
		} else {
			ec.renewalErrors++
		}
		ec.mu.Unlock()
		
		ec.logger.Error("Failed to acquire/renew lease",
			"identity", ec.config.Identity,
			"error", err)
		
		// If we were the leader but failed to renew, step down
		if ec.isLeader {
			ec.stepDown()
		}
		return
	}
	
	// Get current lease info to check who the leader is
	leaseInfo, err := ec.leaseManager.GetLeaseInfo(ctx)
	if err != nil {
		ec.logger.Error("Failed to get lease info",
			"identity", ec.config.Identity,
			"error", err)
		return
	}
	
	ec.updateLeadershipState(acquired, leaseInfo)
}

// updateLeadershipState updates the internal state based on lease acquisition results
func (ec *ElectionController) updateLeadershipState(acquired bool, leaseInfo *LeaseInfo) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	
	wasLeader := ec.isLeader
	oldLeader := ec.currentLeader
	
	ec.isLeader = acquired
	ec.currentLeader = leaseInfo.HolderIdentity
	
	// Check if leadership changed
	leadershipChanged := wasLeader != ec.isLeader
	leaderChanged := oldLeader != ec.currentLeader
	
	if leadershipChanged || leaderChanged {
		ec.lastLeaderChange = time.Now()
		ec.leadershipChanges++
		
		ec.logger.Info("Leadership state changed",
			"identity", ec.config.Identity,
			"wasLeader", wasLeader,
			"isLeader", ec.isLeader,
			"currentLeader", ec.currentLeader,
			"transitions", leaseInfo.LeaseTransitions)
	}
	
	// Handle leadership transitions
	if leadershipChanged {
		if ec.isLeader {
			ec.logger.Info("Became leader",
				"identity", ec.config.Identity,
				"transitions", leaseInfo.LeaseTransitions)
			
			// Call the callback outside of the lock
			go func() {
				if ec.callbacks.OnStartedLeading != nil {
					ec.callbacks.OnStartedLeading(context.Background())
				}
			}()
		} else {
			ec.logger.Info("Lost leadership",
				"identity", ec.config.Identity,
				"currentLeader", ec.currentLeader)
			
			// Call the callback outside of the lock
			go func() {
				if ec.callbacks.OnStoppedLeading != nil {
					ec.callbacks.OnStoppedLeading()
				}
			}()
		}
	}
	
	// Handle leader change notifications
	if leaderChanged && ec.callbacks.OnNewLeader != nil {
		go func() {
			ec.callbacks.OnNewLeader(ec.currentLeader)
		}()
	}
}

// stepDown forces this instance to step down from leadership
func (ec *ElectionController) stepDown() {
	ec.mu.Lock()
	wasLeader := ec.isLeader
	ec.isLeader = false
	ec.mu.Unlock()
	
	if wasLeader {
		ec.logger.Warn("Stepping down from leadership due to lease renewal failure",
			"identity", ec.config.Identity)
		
		if ec.callbacks.OnStoppedLeading != nil {
			go ec.callbacks.OnStoppedLeading()
		}
	}
}

// releaseLeadershipOnExit releases leadership when the controller stops
func (ec *ElectionController) releaseLeadershipOnExit(ctx context.Context) {
	ec.mu.Lock()
	wasLeader := ec.isLeader
	ec.isLeader = false
	ec.mu.Unlock()
	
	if wasLeader {
		ec.logger.Info("Releasing leadership on exit", "identity", ec.config.Identity)
		
		// Create a timeout context for lease release
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		if err := ec.leaseManager.ReleaseLease(releaseCtx); err != nil {
			ec.logger.Error("Failed to release lease on exit",
				"identity", ec.config.Identity,
				"error", err)
		}
		
		if ec.callbacks.OnStoppedLeading != nil {
			ec.callbacks.OnStoppedLeading()
		}
	}
}

// ElectionMetrics contains metrics about the election process
type ElectionMetrics struct {
	IsLeader          bool
	CurrentLeader     string
	LeadershipChanges int64
	AcquisitionErrors int64
	RenewalErrors     int64
	LastLeaderChange  time.Time
}