package auth

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault-client-go"
)

func TestDetectAuthMethod(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected AuthMethod
	}{
		{
			name: "explicit token method",
			envVars: map[string]string{
				"VAULT_AUTH_METHOD": "token",
				"VAULT_TOKEN":       "test-token",
			},
			expected: AuthMethodToken,
		},
		{
			name: "detect kubernetes",
			envVars: map[string]string{
				"KUBERNETES_SERVICE_HOST": "10.0.0.1",
			},
			expected: "", // Would be AuthMethodKubernetes if token file exists
		},
		{
			name: "detect approle",
			envVars: map[string]string{
				"VAULT_ROLE_ID": "test-role-id",
			},
			expected: AuthMethodAppRole,
		},
		{
			name: "fallback to token",
			envVars: map[string]string{
				"VAULT_TOKEN": "test-token",
			},
			expected: AuthMethodToken,
		},
		{
			name:     "no method detected",
			envVars:  map[string]string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			os.Clearenv()

			// Set test environment variables
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			// Test detection
			result := detectAuthMethod()
			if result != tt.expected {
				t.Errorf("detectAuthMethod() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestNewAuthConfigFromEnvironment(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		check   func(*AuthConfig) bool
	}{
		{
			name: "token config",
			envVars: map[string]string{
				"VAULT_ADDR":  "https://vault.example.com",
				"VAULT_TOKEN": "test-token",
			},
			check: func(c *AuthConfig) bool {
				return c.Method == AuthMethodToken &&
					c.Token != nil &&
					c.Token.Token == "test-token" &&
					c.VaultAddr == "https://vault.example.com"
			},
		},
		{
			name: "approle config",
			envVars: map[string]string{
				"VAULT_ADDR":               "https://vault.example.com",
				"VAULT_ROLE_ID":            "role-id",
				"VAULT_SECRET_ID":          "secret-id",
				"VAULT_APPROLE_MOUNT_PATH": "custom-approle",
			},
			check: func(c *AuthConfig) bool {
				return c.Method == AuthMethodAppRole &&
					c.AppRole != nil &&
					c.AppRole.RoleID == "role-id" &&
					c.AppRole.SecretID == "secret-id" &&
					c.AppRole.MountPath == "custom-approle"
			},
		},
		{
			name: "kubernetes config with explicit method",
			envVars: map[string]string{
				"VAULT_ADDR":           "https://vault.example.com",
				"VAULT_AUTH_METHOD":    "kubernetes", // Explicit method to bypass file check
				"VAULT_K8S_ROLE":       "my-role",
				"VAULT_K8S_MOUNT_PATH": "k8s-auth",
			},
			check: func(c *AuthConfig) bool {
				return c.Method == AuthMethodKubernetes &&
					c.Kubernetes != nil &&
					c.Kubernetes.Role == "my-role" &&
					c.Kubernetes.MountPath == "k8s-auth"
			},
		},
		{
			name: "auto renew disabled",
			envVars: map[string]string{
				"VAULT_TOKEN":      "test-token",
				"VAULT_AUTO_RENEW": "false",
			},
			check: func(c *AuthConfig) bool {
				return !c.AutoRenew
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			os.Clearenv()

			// Set test environment variables
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			// Create config from environment
			config := NewAuthConfigFromEnvironment()

			// Check result
			if !tt.check(config) {
				t.Errorf("NewAuthConfigFromEnvironment() failed validation")
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *AuthConfig
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "missing vault address",
			config: &AuthConfig{
				Method: AuthMethodToken,
			},
			wantErr: true,
		},
		{
			name: "valid token config",
			config: &AuthConfig{
				Method:    AuthMethodToken,
				VaultAddr: "https://vault.example.com",
				Token: &TokenConfig{
					Token: "test-token",
				},
			},
			wantErr: false,
		},
		{
			name: "missing token",
			config: &AuthConfig{
				Method:    AuthMethodToken,
				VaultAddr: "https://vault.example.com",
				Token:     &TokenConfig{},
			},
			wantErr: true,
		},
		{
			name: "valid kubernetes config",
			config: &AuthConfig{
				Method:    AuthMethodKubernetes,
				VaultAddr: "https://vault.example.com",
				Kubernetes: &KubernetesConfig{
					Role: "my-role",
				},
			},
			wantErr: false,
		},
		{
			name: "missing kubernetes role",
			config: &AuthConfig{
				Method:     AuthMethodKubernetes,
				VaultAddr:  "https://vault.example.com",
				Kubernetes: &KubernetesConfig{},
			},
			wantErr: true,
		},
		{
			name: "valid approle config",
			config: &AuthConfig{
				Method:    AuthMethodAppRole,
				VaultAddr: "https://vault.example.com",
				AppRole: &AppRoleConfig{
					RoleID: "role-id",
				},
			},
			wantErr: false,
		},
		{
			name: "unsupported method",
			config: &AuthConfig{
				Method:    "unsupported",
				VaultAddr: "https://vault.example.com",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBaseAuthenticatorShouldRenew(t *testing.T) {
	tests := []struct {
		name        string
		ttl         time.Duration
		elapsed     time.Duration
		renewBuffer time.Duration
		want        bool
	}{
		{
			name:        "should renew - time to renew",
			ttl:         10 * time.Minute,
			elapsed:     6 * time.Minute,
			renewBuffer: 5 * time.Minute,
			want:        true,
		},
		{
			name:        "should not renew - plenty of time",
			ttl:         10 * time.Minute,
			elapsed:     2 * time.Minute,
			renewBuffer: 5 * time.Minute,
			want:        false,
		},
		{
			name:        "non-renewable token",
			ttl:         0,
			elapsed:     5 * time.Minute,
			renewBuffer: 5 * time.Minute,
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BaseAuthenticator{
				TokenTTL:    tt.ttl,
				LastRenewal: time.Now().Add(-tt.elapsed),
				RenewBuffer: tt.renewBuffer,
			}

			if got := b.ShouldRenew(); got != tt.want {
				t.Errorf("ShouldRenew() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthError(t *testing.T) {
	err := NewAuthError(
		AuthMethodToken,
		"authenticate",
		ErrAuthenticationFailed,
		"test message",
	)

	// Test Error() method
	errStr := err.Error()
	if errStr == "" {
		t.Error("AuthError.Error() returned empty string")
	}

	// Test Unwrap()
	if err.Unwrap() != ErrAuthenticationFailed {
		t.Error("AuthError.Unwrap() did not return the wrapped error")
	}
}

func TestManagerCalculateRenewalSleep(t *testing.T) {
	tests := []struct {
		name     string
		ttl      time.Duration
		expected time.Duration
	}{
		{
			name:     "normal TTL",
			ttl:      2 * time.Hour,
			expected: time.Hour,
		},
		{
			name:     "very short TTL",
			ttl:      10 * time.Second,
			expected: 10 * time.Second, // minimum
		},
		{
			name:     "very long TTL",
			ttl:      4 * time.Hour,
			expected: time.Hour, // maximum
		},
		{
			name:     "non-renewable",
			ttl:      0,
			expected: time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manager{
				authenticator: &mockAuthenticator{ttl: tt.ttl},
			}

			result := m.calculateRenewalSleep()
			if result != tt.expected {
				t.Errorf("calculateRenewalSleep() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// mockAuthenticator is a mock implementation for testing
type mockAuthenticator struct {
	ttl time.Duration
}

func (m *mockAuthenticator) Authenticate(ctx context.Context) (*vault.Client, error) {
	return nil, nil
}

func (m *mockAuthenticator) Renew(ctx context.Context, client *vault.Client) error {
	return nil
}

func (m *mockAuthenticator) ShouldRenew() bool {
	return false
}

func (m *mockAuthenticator) Revoke(ctx context.Context, client *vault.Client) error {
	return nil
}

func (m *mockAuthenticator) GetMethod() AuthMethod {
	return AuthMethodToken
}

func (m *mockAuthenticator) GetTokenTTL() time.Duration {
	return m.ttl
}
