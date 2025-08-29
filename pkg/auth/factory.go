package auth

import (
	"fmt"
	"os"
	"strings"
)

// NewAuthenticator creates an authenticator based on the provided configuration
func NewAuthenticator(config *AuthConfig) (Authenticator, error) {
	if config == nil {
		return nil, fmt.Errorf("auth config is required")
	}

	// If no method specified, try to auto-detect
	if config.Method == "" {
		config.Method = detectAuthMethod()
		if config.Method == "" {
			return nil, ErrNoAuthMethod
		}
	}

	// Get Vault address
	vaultAddr := config.VaultAddr
	if vaultAddr == "" {
		vaultAddr = os.Getenv("VAULT_ADDR")
		if vaultAddr == "" {
			return nil, fmt.Errorf("vault address is required (set VAULT_ADDR)")
		}
	}

	// Create authenticator based on method
	switch config.Method {
	case AuthMethodToken:
		return NewTokenAuth(config.Token, vaultAddr)

	case AuthMethodKubernetes:
		return NewKubernetesAuth(config.Kubernetes, vaultAddr)

	case AuthMethodAppRole:
		return NewAppRoleAuth(config.AppRole, vaultAddr)

	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAuthMethod, config.Method)
	}
}

// detectAuthMethod attempts to detect the authentication method from environment
func detectAuthMethod() AuthMethod {
	// Check explicit method first
	if method := os.Getenv("VAULT_AUTH_METHOD"); method != "" {
		return AuthMethod(strings.ToLower(method))
	}

	// Check for Kubernetes environment
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
			return AuthMethodKubernetes
		}
	}

	// Check for AppRole credentials
	if os.Getenv("VAULT_ROLE_ID") != "" {
		return AuthMethodAppRole
	}

	// Check for token
	if os.Getenv("VAULT_TOKEN") != "" {
		return AuthMethodToken
	}

	return ""
}

// NewAuthConfigFromEnvironment creates an AuthConfig from environment variables
func NewAuthConfigFromEnvironment() *AuthConfig {
	config := &AuthConfig{
		Method:    detectAuthMethod(),
		VaultAddr: os.Getenv("VAULT_ADDR"),
		AutoRenew: true, // Default to auto-renew
	}

	// Parse auto-renew setting
	if autoRenew := os.Getenv("VAULT_AUTO_RENEW"); autoRenew != "" {
		config.AutoRenew = strings.ToLower(autoRenew) != "false"
	}

	// Configure based on detected method
	switch config.Method {
	case AuthMethodToken:
		config.Token = &TokenConfig{
			Token: os.Getenv("VAULT_TOKEN"),
		}

	case AuthMethodKubernetes:
		config.Kubernetes = &KubernetesConfig{
			Role:               os.Getenv("VAULT_K8S_ROLE"),
			MountPath:          os.Getenv("VAULT_K8S_MOUNT_PATH"),
			ServiceAccountPath: os.Getenv("VAULT_K8S_SERVICE_ACCOUNT_PATH"),
		}

	case AuthMethodAppRole:
		config.AppRole = &AppRoleConfig{
			RoleID:    os.Getenv("VAULT_ROLE_ID"),
			SecretID:  os.Getenv("VAULT_SECRET_ID"),
			MountPath: os.Getenv("VAULT_APPROLE_MOUNT_PATH"),
		}
	}

	return config
}

// ValidateConfig validates the authentication configuration
func ValidateConfig(config *AuthConfig) error {
	if config == nil {
		return fmt.Errorf("config is nil")
	}

	if config.VaultAddr == "" {
		return fmt.Errorf("vault address is required")
	}

	switch config.Method {
	case AuthMethodToken:
		if config.Token == nil || config.Token.Token == "" {
			return fmt.Errorf("token is required for token auth")
		}

	case AuthMethodKubernetes:
		if config.Kubernetes == nil || config.Kubernetes.Role == "" {
			return fmt.Errorf("role is required for kubernetes auth")
		}

	case AuthMethodAppRole:
		if config.AppRole == nil || config.AppRole.RoleID == "" {
			return fmt.Errorf("role_id is required for approle auth")
		}

	case "":
		return fmt.Errorf("authentication method is required")

	default:
		return fmt.Errorf("unsupported authentication method: %s", config.Method)
	}

	return nil
}
