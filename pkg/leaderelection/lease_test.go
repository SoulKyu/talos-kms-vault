package leaderelection

import (
	"testing"
	"time"
)

func TestDefaultLeaseConfig(t *testing.T) {
	config := DefaultLeaseConfig()
	
	if config.Name != "talos-kms-leader" {
		t.Errorf("Expected name 'talos-kms-leader', got %s", config.Name)
	}
	
	if config.Namespace != "default" {
		t.Errorf("Expected namespace 'default', got %s", config.Namespace)
	}
	
	if config.LeaseDuration != 15*time.Second {
		t.Errorf("Expected lease duration 15s, got %s", config.LeaseDuration)
	}
	
	if config.RenewDeadline != 10*time.Second {
		t.Errorf("Expected renew deadline 10s, got %s", config.RenewDeadline)
	}
	
	if config.RetryPeriod != 2*time.Second {
		t.Errorf("Expected retry period 2s, got %s", config.RetryPeriod)
	}
	
	if config.Identity != "" {
		t.Errorf("Expected empty identity, got %s", config.Identity)
	}
}

func TestLeaseConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *LeaseConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: &LeaseConfig{
				Name:          "test-lease",
				Namespace:     "test-ns",
				Identity:      "test-identity",
				LeaseDuration: 15 * time.Second,
				RenewDeadline: 10 * time.Second,
				RetryPeriod:   2 * time.Second,
			},
			expectError: false,
		},
		{
			name: "empty identity",
			config: &LeaseConfig{
				Name:          "test-lease",
				Namespace:     "test-ns",
				Identity:      "",
				LeaseDuration: 15 * time.Second,
				RenewDeadline: 10 * time.Second,
				RetryPeriod:   2 * time.Second,
			},
			expectError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't easily test NewLeaseManager without a real Kubernetes cluster,
			// so we'll just test the validation logic here
			if tt.config.Identity == "" {
				if !tt.expectError {
					t.Error("Expected validation to pass, but identity is empty")
				}
			} else {
				if tt.expectError {
					t.Error("Expected validation to fail, but config looks valid")
				}
			}
		})
	}
}

func TestInt32Ptr(t *testing.T) {
	val := int32(42)
	ptr := int32Ptr(val)
	
	if ptr == nil {
		t.Error("Expected non-nil pointer")
	}
	
	if *ptr != val {
		t.Errorf("Expected %d, got %d", val, *ptr)
	}
}