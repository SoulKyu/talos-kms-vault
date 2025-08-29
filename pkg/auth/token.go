package auth

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

// TokenAuthenticator implements token-based authentication
type TokenAuthenticator struct {
	BaseAuthenticator
	token string
}

// NewTokenAuth creates a new token authenticator
func NewTokenAuth(config *TokenConfig, vaultAddr string) (*TokenAuthenticator, error) {
	if config == nil {
		return nil, NewAuthError(AuthMethodToken, "new", ErrMissingConfiguration, "token configuration is required")
	}
	
	token := config.Token
	if token == "" {
		// Try to get token from environment
		token = os.Getenv("VAULT_TOKEN")
		if token == "" {
			return nil, NewAuthError(AuthMethodToken, "new", ErrMissingConfiguration, "token is required")
		}
	}
	
	return &TokenAuthenticator{
		BaseAuthenticator: BaseAuthenticator{
			Method:      AuthMethodToken,
			VaultAddr:   vaultAddr,
			RenewBuffer: 5 * time.Minute, // Default renewal buffer
		},
		token: token,
	}, nil
}

// Authenticate performs token authentication
func (t *TokenAuthenticator) Authenticate(ctx context.Context) (*vault.Client, error) {
	// Create client with token
	client, err := vault.New(
		vault.WithAddress(t.VaultAddr),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		return nil, NewAuthError(AuthMethodToken, "authenticate", err, "failed to create vault client")
	}
	
	// Set the token
	if err := client.SetToken(t.token); err != nil {
		return nil, NewAuthError(AuthMethodToken, "authenticate", err, "failed to set token")
	}
	
	// Validate token by looking it up
	resp, err := client.Auth.TokenLookUpSelf(ctx)
	if err != nil {
		return nil, NewAuthError(AuthMethodToken, "authenticate", err, "token validation failed")
	}
	
	// Extract TTL from response
	if ttl, ok := resp.Data["ttl"].(float64); ok {
		t.TokenTTL = time.Duration(ttl) * time.Second
		t.LastRenewal = time.Now()
	}
	
	return client, nil
}

// Renew renews the token
func (t *TokenAuthenticator) Renew(ctx context.Context, client *vault.Client) error {
	// Check if token is renewable
	resp, err := client.Auth.TokenLookUpSelf(ctx)
	if err != nil {
		return NewAuthError(AuthMethodToken, "renew", err, "failed to lookup token")
	}
	
	renewable, ok := resp.Data["renewable"].(bool)
	if !ok || !renewable {
		return NewAuthError(AuthMethodToken, "renew", ErrTokenRenewalFailed, "token is not renewable")
	}
	
	// Renew the token
	renewResp, err := client.Auth.TokenRenewSelf(ctx, schema.TokenRenewSelfRequest{})
	if err != nil {
		return NewAuthError(AuthMethodToken, "renew", err, "failed to renew token")
	}
	
	// Update TTL
	if auth := renewResp.Auth; auth != nil {
		t.TokenTTL = time.Duration(auth.LeaseDuration) * time.Second
		t.LastRenewal = time.Now()
	}
	
	return nil
}

// Revoke revokes the token
func (t *TokenAuthenticator) Revoke(ctx context.Context, client *vault.Client) error {
	_, err := client.Auth.TokenRevokeSelf(ctx)
	if err != nil {
		return NewAuthError(AuthMethodToken, "revoke", err, "failed to revoke token")
	}
	return nil
}

// GetToken returns the token (for backward compatibility)
func (t *TokenAuthenticator) GetToken() string {
	return t.token
}

// ValidateToken checks if the token is still valid
func (t *TokenAuthenticator) ValidateToken(ctx context.Context, client *vault.Client) error {
	_, err := client.Auth.TokenLookUpSelf(ctx)
	if err != nil {
		return fmt.Errorf("token validation failed: %w", err)
	}
	return nil
}