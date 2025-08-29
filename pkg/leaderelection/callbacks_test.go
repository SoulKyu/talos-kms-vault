package leaderelection

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestDefaultIdentity(t *testing.T) {
	// Save original environment
	originalPodName := os.Getenv("POD_NAME")
	originalIdentity := os.Getenv("LEADER_ELECTION_IDENTITY")

	// Clean up after test
	defer func() {
		os.Setenv("POD_NAME", originalPodName)
		os.Setenv("LEADER_ELECTION_IDENTITY", originalIdentity)
	}()

	tests := []struct {
		name           string
		setupEnv       func()
		expectedPrefix string // We can't predict exact hostname
	}{
		{
			name: "with explicit identity",
			setupEnv: func() {
				os.Setenv("LEADER_ELECTION_IDENTITY", "explicit-identity")
				os.Unsetenv("POD_NAME")
			},
			expectedPrefix: "explicit-identity",
		},
		{
			name: "with pod name",
			setupEnv: func() {
				os.Unsetenv("LEADER_ELECTION_IDENTITY")
				os.Setenv("POD_NAME", "pod-123")
			},
			expectedPrefix: "pod-123",
		},
		{
			name: "fallback to hostname",
			setupEnv: func() {
				os.Unsetenv("LEADER_ELECTION_IDENTITY")
				os.Unsetenv("POD_NAME")
			},
			expectedPrefix: "", // Will be hostname, we can't predict it
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupEnv()
			identity := DefaultIdentity()

			if tt.expectedPrefix != "" && identity != tt.expectedPrefix {
				t.Errorf("Expected identity %s, got %s", tt.expectedPrefix, identity)
			}

			if identity == "" {
				t.Error("Identity should not be empty")
			}
		})
	}
}

func TestGetNamespaceFromEnv(t *testing.T) {
	// Save original environment
	originalPodNS := os.Getenv("POD_NAMESPACE")
	originalElectionNS := os.Getenv("LEADER_ELECTION_NAMESPACE")

	// Clean up after test
	defer func() {
		os.Setenv("POD_NAMESPACE", originalPodNS)
		os.Setenv("LEADER_ELECTION_NAMESPACE", originalElectionNS)
	}()

	tests := []struct {
		name     string
		setupEnv func()
		expected string
	}{
		{
			name: "with explicit namespace",
			setupEnv: func() {
				os.Setenv("LEADER_ELECTION_NAMESPACE", "custom-ns")
			},
			expected: "custom-ns",
		},
		{
			name: "with pod namespace",
			setupEnv: func() {
				os.Unsetenv("LEADER_ELECTION_NAMESPACE")
				os.Setenv("POD_NAMESPACE", "pod-ns")
			},
			expected: "pod-ns",
		},
		{
			name: "default namespace",
			setupEnv: func() {
				os.Unsetenv("LEADER_ELECTION_NAMESPACE")
				os.Unsetenv("POD_NAMESPACE")
			},
			expected: "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupEnv()
			ns := GetNamespaceFromEnv()

			if ns != tt.expected {
				t.Errorf("Expected namespace %s, got %s", tt.expected, ns)
			}
		})
	}
}

func TestGetLeaseNameFromEnv(t *testing.T) {
	// Save original environment
	originalName := os.Getenv("LEADER_ELECTION_NAME")

	// Clean up after test
	defer func() {
		os.Setenv("LEADER_ELECTION_NAME", originalName)
	}()

	tests := []struct {
		name     string
		setupEnv func()
		expected string
	}{
		{
			name: "with custom name",
			setupEnv: func() {
				os.Setenv("LEADER_ELECTION_NAME", "custom-leader")
			},
			expected: "custom-leader",
		},
		{
			name: "default name",
			setupEnv: func() {
				os.Unsetenv("LEADER_ELECTION_NAME")
			},
			expected: "talos-kms-leader",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupEnv()
			name := GetLeaseNameFromEnv()

			if name != tt.expected {
				t.Errorf("Expected lease name %s, got %s", tt.expected, name)
			}
		})
	}
}

func TestCallbackBuilder(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	builder := NewCallbackBuilder(logger)

	if builder == nil {
		t.Fatal("Expected non-nil callback builder")
	}

	if builder.logger != logger {
		t.Error("Expected logger to be set correctly")
	}
}

func TestBuildLoggingCallbacks(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	builder := NewCallbackBuilder(logger)

	callbacks := builder.BuildLoggingCallbacks()

	// Test that callbacks are not nil
	if callbacks.OnStartedLeading == nil {
		t.Error("OnStartedLeading callback should not be nil")
	}

	if callbacks.OnStoppedLeading == nil {
		t.Error("OnStoppedLeading callback should not be nil")
	}

	if callbacks.OnNewLeader == nil {
		t.Error("OnNewLeader callback should not be nil")
	}

	// Test that callbacks don't panic when called
	ctx := context.Background()

	// These should not panic
	callbacks.OnStartedLeading(ctx)
	callbacks.OnStoppedLeading()
	callbacks.OnNewLeader("test-leader")
}

func TestBuildGracefulShutdownCallbacks(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	builder := NewCallbackBuilder(logger)

	becameLeaderCalled := false
	lostLeadershipCalled := false

	onBecomeLeader := func(ctx context.Context) {
		becameLeaderCalled = true
	}

	onLoseLeadership := func() {
		lostLeadershipCalled = true
	}

	callbacks := builder.BuildGracefulShutdownCallbacks(
		onBecomeLeader,
		onLoseLeadership,
		100*time.Millisecond,
	)

	// Test callbacks are not nil
	if callbacks.OnStartedLeading == nil {
		t.Error("OnStartedLeading callback should not be nil")
	}

	if callbacks.OnStoppedLeading == nil {
		t.Error("OnStoppedLeading callback should not be nil")
	}

	// Test that callbacks work
	ctx := context.Background()
	callbacks.OnStartedLeading(ctx)

	// Give it a moment to execute
	time.Sleep(50 * time.Millisecond)

	if !becameLeaderCalled {
		t.Error("Expected onBecomeLeader to be called")
	}

	callbacks.OnStoppedLeading()

	// Give it a moment to execute
	time.Sleep(50 * time.Millisecond)

	if !lostLeadershipCalled {
		t.Error("Expected onLoseLeadership to be called")
	}
}
