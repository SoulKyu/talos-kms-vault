package auth

import (
	"context"
	"os"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

const (
	defaultAppRoleMountPath = "approle"
)

// AppRoleAuthenticator implements AppRole-based authentication
type AppRoleAuthenticator struct {
	BaseAuthenticator
	roleID    string
	secretID  string
	mountPath string
}

// NewAppRoleAuth creates a new AppRole authenticator
func NewAppRoleAuth(config *AppRoleConfig, vaultAddr string) (*AppRoleAuthenticator, error) {
	if config == nil {
		config = &AppRoleConfig{}
	}

	// Set defaults
	if config.MountPath == "" {
		config.MountPath = defaultAppRoleMountPath
	}

	// Get RoleID
	if config.RoleID == "" {
		config.RoleID = os.Getenv("VAULT_ROLE_ID")
		if config.RoleID == "" {
			return nil, NewAuthError(AuthMethodAppRole, "new", ErrMissingConfiguration, "role_id is required")
		}
	}

	// Get SecretID
	if config.SecretID == "" {
		config.SecretID = os.Getenv("VAULT_SECRET_ID")
		// SecretID might be optional for some AppRole configurations
	}

	return &AppRoleAuthenticator{
		BaseAuthenticator: BaseAuthenticator{
			Method:      AuthMethodAppRole,
			VaultAddr:   vaultAddr,
			RenewBuffer: 5 * time.Minute,
		},
		roleID:    config.RoleID,
		secretID:  config.SecretID,
		mountPath: config.MountPath,
	}, nil
}

// Authenticate performs AppRole authentication
func (a *AppRoleAuthenticator) Authenticate(ctx context.Context) (*vault.Client, error) {
	// Create Vault client
	client, err := vault.New(
		vault.WithAddress(a.VaultAddr),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		return nil, NewAuthError(AuthMethodAppRole, "authenticate", err, "failed to create vault client")
	}

	// Prepare login request
	loginReq := schema.AppRoleLoginRequest{
		RoleId: a.roleID,
	}

	// Add SecretID if provided
	if a.secretID != "" {
		loginReq.SecretId = a.secretID
	}

	// Perform AppRole login
	resp, err := client.Auth.AppRoleLogin(ctx, loginReq, vault.WithMountPath(a.mountPath))
	if err != nil {
		return nil, NewAuthError(AuthMethodAppRole, "authenticate", err, "approle login failed")
	}

	// Check response
	if resp.Auth == nil || resp.Auth.ClientToken == "" {
		return nil, NewAuthError(AuthMethodAppRole, "authenticate", ErrAuthenticationFailed, "no token received from Vault")
	}

	// Set the token
	if err := client.SetToken(resp.Auth.ClientToken); err != nil {
		return nil, NewAuthError(AuthMethodAppRole, "authenticate", err, "failed to set token")
	}

	// Store TTL and metadata
	a.TokenTTL = time.Duration(resp.Auth.LeaseDuration) * time.Second
	a.LastRenewal = time.Now()

	// Handle wrapped SecretID response if applicable
	if resp.Auth.Metadata != nil {
		if wrappedSecretID, ok := resp.Auth.Metadata["wrapped_secret_id"]; ok && wrappedSecretID != "" {
			// Store for potential future use
			a.secretID = wrappedSecretID
		}
	}

	return client, nil
}

// Renew renews the AppRole auth token
func (a *AppRoleAuthenticator) Renew(ctx context.Context, client *vault.Client) error {
	// Try to renew the existing token
	renewResp, err := client.Auth.TokenRenewSelf(ctx, schema.TokenRenewSelfRequest{})
	if err != nil {
		// If renewal fails and we have credentials, try to re-authenticate
		if a.roleID != "" {
			// Re-authenticate
			loginReq := schema.AppRoleLoginRequest{
				RoleId: a.roleID,
			}

			if a.secretID != "" {
				loginReq.SecretId = a.secretID
			}

			resp, err := client.Auth.AppRoleLogin(ctx, loginReq, vault.WithMountPath(a.mountPath))
			if err != nil {
				return NewAuthError(AuthMethodAppRole, "renew", err, "re-authentication failed")
			}

			if resp.Auth != nil && resp.Auth.ClientToken != "" {
				if err := client.SetToken(resp.Auth.ClientToken); err != nil {
					return NewAuthError(AuthMethodAppRole, "renew", err, "failed to set new token")
				}
				a.TokenTTL = time.Duration(resp.Auth.LeaseDuration) * time.Second
				a.LastRenewal = time.Now()
				return nil
			}
		}

		return NewAuthError(AuthMethodAppRole, "renew", err, "token renewal failed")
	}

	// Update TTL from renewal response
	if renewResp.Auth != nil {
		a.TokenTTL = time.Duration(renewResp.Auth.LeaseDuration) * time.Second
		a.LastRenewal = time.Now()
	}

	return nil
}

// Revoke revokes the AppRole auth token
func (a *AppRoleAuthenticator) Revoke(ctx context.Context, client *vault.Client) error {
	_, err := client.Auth.TokenRevokeSelf(ctx)
	if err != nil {
		return NewAuthError(AuthMethodAppRole, "revoke", err, "failed to revoke token")
	}
	return nil
}

// RotateSecretID generates a new SecretID for the role
func (a *AppRoleAuthenticator) RotateSecretID(ctx context.Context, client *vault.Client) (string, error) {
	// Generate new SecretID
	resp, err := client.Auth.AppRoleWriteSecretId(
		ctx,
		a.roleID,
		schema.AppRoleWriteSecretIdRequest{},
		vault.WithMountPath(a.mountPath),
	)
	if err != nil {
		return "", NewAuthError(AuthMethodAppRole, "rotate_secret_id", err, "failed to generate new secret_id")
	}

	if resp.Data.SecretId == "" {
		return "", NewAuthError(AuthMethodAppRole, "rotate_secret_id", ErrAuthenticationFailed, "no secret_id in response")
	}

	// Update internal state
	a.secretID = resp.Data.SecretId

	return resp.Data.SecretId, nil
}

// GetRoleID returns the configured role ID
func (a *AppRoleAuthenticator) GetRoleID() string {
	return a.roleID
}
