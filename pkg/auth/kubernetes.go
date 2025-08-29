package auth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

const (
	defaultServiceAccountPath  = "/var/run/secrets/kubernetes.io/serviceaccount"
	defaultKubernetesMountPath = "kubernetes"
)

// KubernetesAuthenticator implements Kubernetes-based authentication
type KubernetesAuthenticator struct {
	BaseAuthenticator
	role               string
	mountPath          string
	serviceAccountPath string
	jwt                string
}

// NewKubernetesAuth creates a new Kubernetes authenticator
func NewKubernetesAuth(config *KubernetesConfig, vaultAddr string) (*KubernetesAuthenticator, error) {
	if config == nil {
		config = &KubernetesConfig{}
	}

	// Set defaults
	if config.ServiceAccountPath == "" {
		config.ServiceAccountPath = defaultServiceAccountPath
	}
	if config.MountPath == "" {
		config.MountPath = defaultKubernetesMountPath
	}

	// Role is required
	if config.Role == "" {
		// Try to get from environment
		config.Role = os.Getenv("VAULT_K8S_ROLE")
		if config.Role == "" {
			return nil, NewAuthError(AuthMethodKubernetes, "new", ErrMissingConfiguration, "role is required")
		}
	}

	// Check if we're running in Kubernetes
	if !isRunningInKubernetes(config.ServiceAccountPath) {
		return nil, NewAuthError(AuthMethodKubernetes, "new", ErrMissingConfiguration, "not running in Kubernetes environment")
	}

	return &KubernetesAuthenticator{
		BaseAuthenticator: BaseAuthenticator{
			Method:      AuthMethodKubernetes,
			VaultAddr:   vaultAddr,
			RenewBuffer: 5 * time.Minute,
		},
		role:               config.Role,
		mountPath:          config.MountPath,
		serviceAccountPath: config.ServiceAccountPath,
	}, nil
}

// Authenticate performs Kubernetes authentication
func (k *KubernetesAuthenticator) Authenticate(ctx context.Context) (*vault.Client, error) {
	// Read JWT from service account
	jwt, err := k.readServiceAccountJWT()
	if err != nil {
		return nil, NewAuthError(AuthMethodKubernetes, "authenticate", err, "failed to read service account JWT")
	}
	k.jwt = jwt

	// Create Vault client
	client, err := vault.New(
		vault.WithAddress(k.VaultAddr),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		return nil, NewAuthError(AuthMethodKubernetes, "authenticate", err, "failed to create vault client")
	}

	// Perform Kubernetes auth
	authReq := schema.KubernetesLoginRequest{
		Jwt:  jwt,
		Role: k.role,
	}

	resp, err := client.Auth.KubernetesLogin(ctx, authReq, vault.WithMountPath(k.mountPath))
	if err != nil {
		return nil, NewAuthError(AuthMethodKubernetes, "authenticate", err, "kubernetes login failed")
	}

	// Set the token
	if resp.Auth == nil || resp.Auth.ClientToken == "" {
		return nil, NewAuthError(AuthMethodKubernetes, "authenticate", ErrAuthenticationFailed, "no token received from Vault")
	}

	if err := client.SetToken(resp.Auth.ClientToken); err != nil {
		return nil, NewAuthError(AuthMethodKubernetes, "authenticate", err, "failed to set token")
	}

	// Store TTL
	k.TokenTTL = time.Duration(resp.Auth.LeaseDuration) * time.Second
	k.LastRenewal = time.Now()

	return client, nil
}

// Renew renews the Kubernetes auth token
func (k *KubernetesAuthenticator) Renew(ctx context.Context, client *vault.Client) error {
	// Try to renew the existing token first
	renewResp, err := client.Auth.TokenRenewSelf(ctx, schema.TokenRenewSelfRequest{})
	if err != nil {
		// If renewal fails, re-authenticate
		newJWT, err := k.readServiceAccountJWT()
		if err != nil {
			return NewAuthError(AuthMethodKubernetes, "renew", err, "failed to read new JWT")
		}

		// Check if JWT has changed (in case of rotation)
		if newJWT != k.jwt {
			// Re-authenticate with new JWT
			authReq := schema.KubernetesLoginRequest{
				Jwt:  newJWT,
				Role: k.role,
			}

			resp, err := client.Auth.KubernetesLogin(ctx, authReq, vault.WithMountPath(k.mountPath))
			if err != nil {
				return NewAuthError(AuthMethodKubernetes, "renew", err, "re-authentication failed")
			}

			if resp.Auth != nil && resp.Auth.ClientToken != "" {
				if err := client.SetToken(resp.Auth.ClientToken); err != nil {
					return NewAuthError(AuthMethodKubernetes, "renew", err, "failed to set new token")
				}
				k.jwt = newJWT
				k.TokenTTL = time.Duration(resp.Auth.LeaseDuration) * time.Second
				k.LastRenewal = time.Now()
				return nil
			}
		}

		return NewAuthError(AuthMethodKubernetes, "renew", err, "token renewal failed")
	}

	// Update TTL from renewal response
	if renewResp.Auth != nil {
		k.TokenTTL = time.Duration(renewResp.Auth.LeaseDuration) * time.Second
		k.LastRenewal = time.Now()
	}

	return nil
}

// Revoke revokes the Kubernetes auth token
func (k *KubernetesAuthenticator) Revoke(ctx context.Context, client *vault.Client) error {
	_, err := client.Auth.TokenRevokeSelf(ctx)
	if err != nil {
		return NewAuthError(AuthMethodKubernetes, "revoke", err, "failed to revoke token")
	}
	return nil
}

// readServiceAccountJWT reads the JWT from the service account token file
func (k *KubernetesAuthenticator) readServiceAccountJWT() (string, error) {
	tokenPath := filepath.Join(k.serviceAccountPath, "token")
	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read service account token: %w", err)
	}

	return strings.TrimSpace(string(tokenBytes)), nil
}

// isRunningInKubernetes checks if we're running in a Kubernetes pod
func isRunningInKubernetes(serviceAccountPath string) bool {
	// Check for service account token
	tokenPath := filepath.Join(serviceAccountPath, "token")
	if _, err := os.Stat(tokenPath); err != nil {
		return false
	}

	// Also check for Kubernetes environment variables
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}

	return false
}

// GetRole returns the configured Kubernetes role
func (k *KubernetesAuthenticator) GetRole() string {
	return k.role
}
