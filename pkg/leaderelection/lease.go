package leaderelection

import (
	"context"
	"fmt"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// LeaseConfig holds configuration for leader election leases
type LeaseConfig struct {
	// Name of the lease resource
	Name string
	// Namespace where the lease will be created
	Namespace string
	// Identity of this instance (usually pod name or hostname)
	Identity string
	// Duration that non-leader candidates will wait to force acquire leadership
	LeaseDuration time.Duration
	// Duration that the leader will renew the lease
	RenewDeadline time.Duration
	// Duration that the leader will retry renewing the lease
	RetryPeriod time.Duration
}

// DefaultLeaseConfig returns a default lease configuration
func DefaultLeaseConfig() *LeaseConfig {
	return &LeaseConfig{
		Name:          "talos-kms-leader",
		Namespace:     "default",
		Identity:      "", // Must be set by caller
		LeaseDuration: 15 * time.Second,
		RenewDeadline: 10 * time.Second,
		RetryPeriod:   2 * time.Second,
	}
}

// LeaseManager handles Kubernetes lease operations for leader election
type LeaseManager struct {
	config    *LeaseConfig
	clientset *kubernetes.Clientset
}

// NewLeaseManager creates a new lease manager
func NewLeaseManager(config *LeaseConfig) (*LeaseManager, error) {
	if config.Identity == "" {
		return nil, fmt.Errorf("lease identity cannot be empty")
	}

	// Create in-cluster config
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create in-cluster config: %w", err)
	}

	// Create clientset
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes clientset: %w", err)
	}

	return &LeaseManager{
		config:    config,
		clientset: clientset,
	}, nil
}

// NewLeaseManagerWithConfig creates a lease manager with custom Kubernetes config
func NewLeaseManagerWithConfig(config *LeaseConfig, restConfig *rest.Config) (*LeaseManager, error) {
	if config.Identity == "" {
		return nil, fmt.Errorf("lease identity cannot be empty")
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes clientset: %w", err)
	}

	return &LeaseManager{
		config:    config,
		clientset: clientset,
	}, nil
}

// AcquireLease attempts to acquire or renew the leadership lease
func (lm *LeaseManager) AcquireLease(ctx context.Context) (bool, error) {
	now := metav1.NewMicroTime(time.Now())

	// Try to get existing lease
	lease, err := lm.clientset.CoordinationV1().Leases(lm.config.Namespace).Get(
		ctx, lm.config.Name, metav1.GetOptions{})

	if err != nil {
		// Lease doesn't exist, try to create it
		return lm.createLease(ctx, now)
	}

	// Check if we can acquire the lease
	if lm.canAcquireLease(lease, now) {
		return lm.updateLease(ctx, lease, now)
	}

	return false, nil
}

// createLease creates a new lease with this instance as the leader
func (lm *LeaseManager) createLease(ctx context.Context, now metav1.MicroTime) (bool, error) {
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      lm.config.Name,
			Namespace: lm.config.Namespace,
		},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       &lm.config.Identity,
			LeaseDurationSeconds: int32Ptr(int32(lm.config.LeaseDuration.Seconds())),
			AcquireTime:          &now,
			RenewTime:            &now,
			LeaseTransitions:     int32Ptr(0),
		},
	}

	_, err := lm.clientset.CoordinationV1().Leases(lm.config.Namespace).Create(
		ctx, lease, metav1.CreateOptions{})

	if err != nil {
		return false, fmt.Errorf("failed to create lease: %w", err)
	}

	return true, nil
}

// updateLease updates an existing lease with this instance as the leader
func (lm *LeaseManager) updateLease(ctx context.Context, lease *coordinationv1.Lease, now metav1.MicroTime) (bool, error) {
	wasLeader := lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity == lm.config.Identity

	// Update lease with our identity
	lease.Spec.HolderIdentity = &lm.config.Identity
	lease.Spec.RenewTime = &now

	if !wasLeader {
		lease.Spec.AcquireTime = &now
		if lease.Spec.LeaseTransitions != nil {
			*lease.Spec.LeaseTransitions++
		} else {
			lease.Spec.LeaseTransitions = int32Ptr(1)
		}
	}

	_, err := lm.clientset.CoordinationV1().Leases(lm.config.Namespace).Update(
		ctx, lease, metav1.UpdateOptions{})

	if err != nil {
		return false, fmt.Errorf("failed to update lease: %w", err)
	}

	return true, nil
}

// canAcquireLease determines if this instance can acquire the lease
func (lm *LeaseManager) canAcquireLease(lease *coordinationv1.Lease, now metav1.MicroTime) bool {
	// If we're already the leader, we can always renew
	if lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity == lm.config.Identity {
		return true
	}

	// If there's no current holder, we can acquire it
	if lease.Spec.HolderIdentity == nil {
		return true
	}

	// Check if the lease has expired
	if lease.Spec.RenewTime == nil {
		return true
	}

	leaseDuration := time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second
	expiry := lease.Spec.RenewTime.Add(leaseDuration)

	return now.Time.After(expiry)
}

// ReleaseLease releases the lease if this instance is the current leader
func (lm *LeaseManager) ReleaseLease(ctx context.Context) error {
	lease, err := lm.clientset.CoordinationV1().Leases(lm.config.Namespace).Get(
		ctx, lm.config.Name, metav1.GetOptions{})

	if err != nil {
		return fmt.Errorf("failed to get lease for release: %w", err)
	}

	// Only release if we're the current holder
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != lm.config.Identity {
		return nil // Not our lease to release
	}

	// Clear the holder identity
	lease.Spec.HolderIdentity = nil
	lease.Spec.RenewTime = nil
	lease.Spec.AcquireTime = nil

	_, err = lm.clientset.CoordinationV1().Leases(lm.config.Namespace).Update(
		ctx, lease, metav1.UpdateOptions{})

	if err != nil {
		return fmt.Errorf("failed to release lease: %w", err)
	}

	return nil
}

// GetLeaseInfo returns information about the current lease
func (lm *LeaseManager) GetLeaseInfo(ctx context.Context) (*LeaseInfo, error) {
	lease, err := lm.clientset.CoordinationV1().Leases(lm.config.Namespace).Get(
		ctx, lm.config.Name, metav1.GetOptions{})

	if err != nil {
		return nil, fmt.Errorf("failed to get lease info: %w", err)
	}

	info := &LeaseInfo{
		Name:      lease.Name,
		Namespace: lease.Namespace,
	}

	if lease.Spec.HolderIdentity != nil {
		info.HolderIdentity = *lease.Spec.HolderIdentity
		info.IsLeader = info.HolderIdentity == lm.config.Identity
	}

	if lease.Spec.AcquireTime != nil {
		info.AcquireTime = lease.Spec.AcquireTime.Time
	}

	if lease.Spec.RenewTime != nil {
		info.RenewTime = lease.Spec.RenewTime.Time
	}

	if lease.Spec.LeaseTransitions != nil {
		info.LeaseTransitions = *lease.Spec.LeaseTransitions
	}

	if lease.Spec.LeaseDurationSeconds != nil {
		info.LeaseDuration = time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second
	}

	return info, nil
}

// LeaseInfo contains information about the current lease state
type LeaseInfo struct {
	Name             string
	Namespace        string
	HolderIdentity   string
	IsLeader         bool
	AcquireTime      time.Time
	RenewTime        time.Time
	LeaseTransitions int32
	LeaseDuration    time.Duration
}

// int32Ptr returns a pointer to an int32
func int32Ptr(i int32) *int32 {
	return &i
}
