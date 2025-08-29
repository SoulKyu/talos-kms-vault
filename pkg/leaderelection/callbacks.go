package leaderelection

import (
	"context"
	"log/slog"
	"os"
	"time"
)

// CallbackBuilder helps build leader election callbacks with common patterns
type CallbackBuilder struct {
	logger *slog.Logger
}

// NewCallbackBuilder creates a new callback builder
func NewCallbackBuilder(logger *slog.Logger) *CallbackBuilder {
	return &CallbackBuilder{logger: logger}
}

// BuildServerCallbacks creates callbacks that integrate with a server lifecycle
func (cb *CallbackBuilder) BuildServerCallbacks(
	onBecomeLeader func(ctx context.Context),
	onLoseLeadership func(),
	onLeaderChange func(leader string),
) LeaderElectionCallbacks {
	return LeaderElectionCallbacks{
		OnStartedLeading: func(ctx context.Context) {
			cb.logger.Info("Started leading - becoming active")

			if onBecomeLeader != nil {
				onBecomeLeader(ctx)
			}
		},

		OnStoppedLeading: func() {
			cb.logger.Info("Stopped leading - becoming passive")

			if onLoseLeadership != nil {
				onLoseLeadership()
			}
		},

		OnNewLeader: func(identity string) {
			hostname, _ := os.Hostname()
			isCurrentInstance := identity == hostname

			cb.logger.Info("New leader elected",
				"leader", identity,
				"isSelf", isCurrentInstance)

			if onLeaderChange != nil {
				onLeaderChange(identity)
			}
		},
	}
}

// BuildLoggingCallbacks creates simple callbacks that only log events
func (cb *CallbackBuilder) BuildLoggingCallbacks() LeaderElectionCallbacks {
	return LeaderElectionCallbacks{
		OnStartedLeading: func(ctx context.Context) {
			cb.logger.Info("Leadership acquired - this instance is now the leader")
		},

		OnStoppedLeading: func() {
			cb.logger.Info("Leadership lost - this instance is no longer the leader")
		},

		OnNewLeader: func(identity string) {
			cb.logger.Info("Leader election result", "currentLeader", identity)
		},
	}
}

// BuildGracefulShutdownCallbacks creates callbacks that handle graceful shutdown scenarios
func (cb *CallbackBuilder) BuildGracefulShutdownCallbacks(
	onBecomeLeader func(ctx context.Context),
	onLoseLeadership func(),
	gracefulShutdownTimeout time.Duration,
) LeaderElectionCallbacks {
	return LeaderElectionCallbacks{
		OnStartedLeading: func(ctx context.Context) {
			cb.logger.Info("Acquired leadership - transitioning to active state")

			if onBecomeLeader != nil {
				// Execute the callback with a timeout to prevent hanging
				timeoutCtx, cancel := context.WithTimeout(ctx, gracefulShutdownTimeout)
				defer cancel()

				done := make(chan struct{})
				go func() {
					defer close(done)
					onBecomeLeader(timeoutCtx)
				}()

				select {
				case <-done:
					cb.logger.Info("Successfully transitioned to active state")
				case <-timeoutCtx.Done():
					cb.logger.Error("Timeout while transitioning to active state",
						"timeout", gracefulShutdownTimeout)
				}
			}
		},

		OnStoppedLeading: func() {
			cb.logger.Info("Lost leadership - beginning graceful transition to passive state")

			if onLoseLeadership != nil {
				// Execute the callback with a timeout
				ctx, cancel := context.WithTimeout(context.Background(), gracefulShutdownTimeout)
				defer cancel()

				done := make(chan struct{})
				go func() {
					defer close(done)
					onLoseLeadership()
				}()

				select {
				case <-done:
					cb.logger.Info("Successfully transitioned to passive state")
				case <-ctx.Done():
					cb.logger.Error("Timeout while transitioning to passive state",
						"timeout", gracefulShutdownTimeout)
				}
			}
		},

		OnNewLeader: func(identity string) {
			cb.logger.Info("Leader election completed",
				"newLeader", identity,
				"timestamp", time.Now().Format(time.RFC3339))
		},
	}
}

// DefaultIdentity generates a default identity for leader election
// This uses the hostname, but can be overridden by environment variables
func DefaultIdentity() string {
	// Check for explicit identity override
	if identity := os.Getenv("LEADER_ELECTION_IDENTITY"); identity != "" {
		return identity
	}

	// Check for pod name (common in Kubernetes)
	if podName := os.Getenv("POD_NAME"); podName != "" {
		return podName
	}

	// Fall back to hostname
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}

	return hostname
}

// GetNamespaceFromEnv returns the namespace from environment or default
func GetNamespaceFromEnv() string {
	if ns := os.Getenv("LEADER_ELECTION_NAMESPACE"); ns != "" {
		return ns
	}

	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}

	return "default"
}

// GetLeaseNameFromEnv returns the lease name from environment or default
func GetLeaseNameFromEnv() string {
	if name := os.Getenv("LEADER_ELECTION_NAME"); name != "" {
		return name
	}

	return "talos-kms-leader"
}
