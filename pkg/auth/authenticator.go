package auth

import (
	"context"
	"time"

	"github.com/hashicorp/vault-client-go"
)

// AuthMethod represents the type of authentication method
type AuthMethod string

const (
	AuthMethodToken      AuthMethod = "token"
	AuthMethodKubernetes AuthMethod = "kubernetes"
	AuthMethodAppRole    AuthMethod = "approle"
	AuthMethodAWSIAM     AuthMethod = "aws-iam"
)

// Authenticator defines the interface for all authentication methods
type Authenticator interface {
	// Authenticate performs initial authentication and returns a configured Vault client
	Authenticate(ctx context.Context) (*vault.Client, error)
	
	// Renew renews the authentication token
	Renew(ctx context.Context, client *vault.Client) error
	
	// ShouldRenew checks if the token should be renewed
	ShouldRenew() bool
	
	// Revoke revokes the current authentication token
	Revoke(ctx context.Context, client *vault.Client) error
	
	// GetMethod returns the authentication method type
	GetMethod() AuthMethod
	
	// GetTokenTTL returns the current token TTL
	GetTokenTTL() time.Duration
}

// BaseAuthenticator provides common functionality for all authenticators
type BaseAuthenticator struct {
	Method       AuthMethod
	VaultAddr    string
	TokenTTL     time.Duration
	LastRenewal  time.Time
	RenewBuffer  time.Duration // Renew when this much time is left
}

// GetMethod returns the authentication method
func (b *BaseAuthenticator) GetMethod() AuthMethod {
	return b.Method
}

// GetTokenTTL returns the current token TTL
func (b *BaseAuthenticator) GetTokenTTL() time.Duration {
	return b.TokenTTL
}

// ShouldRenew checks if token renewal is needed
func (b *BaseAuthenticator) ShouldRenew() bool {
	if b.TokenTTL == 0 {
		return false // Non-renewable token
	}
	
	elapsed := time.Since(b.LastRenewal)
	remaining := b.TokenTTL - elapsed
	
	// Renew if we have less than RenewBuffer time remaining
	return remaining <= b.RenewBuffer
}

// AuthConfig holds configuration for authentication
type AuthConfig struct {
	Method      AuthMethod
	VaultAddr   string
	AutoRenew   bool
	RenewGrace  time.Duration
	
	// Method-specific configurations
	Token       *TokenConfig
	Kubernetes  *KubernetesConfig
	AppRole     *AppRoleConfig
}

// TokenConfig holds token-specific configuration
type TokenConfig struct {
	Token string
}

// KubernetesConfig holds Kubernetes-specific configuration
type KubernetesConfig struct {
	Role              string
	MountPath         string
	ServiceAccountPath string
}

// AppRoleConfig holds AppRole-specific configuration
type AppRoleConfig struct {
	RoleID    string
	SecretID  string
	MountPath string
}