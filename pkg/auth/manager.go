package auth

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/hashicorp/vault-client-go"
)

// Manager handles authentication lifecycle including renewal
type Manager struct {
	authenticator Authenticator
	client        *vault.Client
	config        *AuthConfig
	logger        *slog.Logger
	
	mu            sync.RWMutex
	cancelRenewal context.CancelFunc
	renewalDone   chan struct{}
}

// NewManager creates a new authentication manager
func NewManager(config *AuthConfig, logger *slog.Logger) (*Manager, error) {
	if config == nil {
		return nil, fmt.Errorf("auth config is required")
	}
	
	if logger == nil {
		logger = slog.Default()
	}
	
	// Create authenticator based on config
	authenticator, err := NewAuthenticator(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticator: %w", err)
	}
	
	return &Manager{
		authenticator: authenticator,
		config:        config,
		logger:        logger.With("component", "auth-manager"),
	}, nil
}

// Start initializes authentication and starts renewal if configured
func (m *Manager) Start(ctx context.Context) error {
	// Perform initial authentication
	client, err := m.authenticator.Authenticate(ctx)
	if err != nil {
		return fmt.Errorf("initial authentication failed: %w", err)
	}
	
	m.mu.Lock()
	m.client = client
	m.mu.Unlock()
	
	m.logger.Info("authentication successful",
		"method", m.authenticator.GetMethod(),
		"ttl", m.authenticator.GetTokenTTL())
	
	// Start renewal if auto-renew is enabled
	if m.config.AutoRenew {
		m.startRenewal()
	}
	
	return nil
}

// Stop stops the renewal process and revokes the token
func (m *Manager) Stop(ctx context.Context) error {
	// Stop renewal
	if m.cancelRenewal != nil {
		m.cancelRenewal()
		// Wait for renewal to stop
		if m.renewalDone != nil {
			select {
			case <-m.renewalDone:
			case <-time.After(5 * time.Second):
				m.logger.Warn("renewal goroutine did not stop in time")
			}
		}
	}
	
	// Revoke token
	m.mu.RLock()
	client := m.client
	m.mu.RUnlock()
	
	if client != nil {
		if err := m.authenticator.Revoke(ctx, client); err != nil {
			m.logger.Error("failed to revoke token", "error", err)
			return err
		}
		m.logger.Info("token revoked successfully")
	}
	
	return nil
}

// GetClient returns the authenticated Vault client
func (m *Manager) GetClient() (*vault.Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.client == nil {
		return nil, fmt.Errorf("not authenticated")
	}
	
	return m.client, nil
}

// startRenewal starts the token renewal goroutine
func (m *Manager) startRenewal() {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancelRenewal = cancel
	m.renewalDone = make(chan struct{})
	
	go m.renewalLoop(ctx)
}

// renewalLoop handles automatic token renewal
func (m *Manager) renewalLoop(ctx context.Context) {
	defer close(m.renewalDone)
	
	// Calculate initial sleep duration
	sleepDuration := m.calculateRenewalSleep()
	
	for {
		select {
		case <-ctx.Done():
			m.logger.Info("renewal loop stopped")
			return
			
		case <-time.After(sleepDuration):
			// Check if renewal is needed
			if !m.authenticator.ShouldRenew() {
				sleepDuration = m.calculateRenewalSleep()
				continue
			}
			
			// Perform renewal
			m.mu.RLock()
			client := m.client
			m.mu.RUnlock()
			
			if client == nil {
				m.logger.Error("client is nil, cannot renew")
				sleepDuration = 10 * time.Second
				continue
			}
			
			err := m.authenticator.Renew(ctx, client)
			if err != nil {
				m.logger.Error("token renewal failed", "error", err)
				
				// Try to re-authenticate
				m.logger.Info("attempting re-authentication")
				newClient, authErr := m.authenticator.Authenticate(ctx)
				if authErr != nil {
					m.logger.Error("re-authentication failed", "error", authErr)
					// Exponential backoff on failure
					sleepDuration = min(sleepDuration*2, 5*time.Minute)
				} else {
					m.mu.Lock()
					m.client = newClient
					m.mu.Unlock()
					
					m.logger.Info("re-authentication successful",
						"ttl", m.authenticator.GetTokenTTL())
					sleepDuration = m.calculateRenewalSleep()
				}
			} else {
				m.logger.Info("token renewed successfully",
					"ttl", m.authenticator.GetTokenTTL())
				sleepDuration = m.calculateRenewalSleep()
			}
		}
	}
}

// calculateRenewalSleep calculates how long to sleep before next renewal check
func (m *Manager) calculateRenewalSleep() time.Duration {
	ttl := m.authenticator.GetTokenTTL()
	if ttl == 0 {
		// Non-renewable token, check every hour
		return time.Hour
	}
	
	// Sleep for half the TTL, but at least 10 seconds and at most 1 hour
	sleep := ttl / 2
	if sleep < 10*time.Second {
		sleep = 10 * time.Second
	} else if sleep > time.Hour {
		sleep = time.Hour
	}
	
	return sleep
}

// ForceRenewal forces an immediate token renewal
func (m *Manager) ForceRenewal(ctx context.Context) error {
	m.mu.RLock()
	client := m.client
	m.mu.RUnlock()
	
	if client == nil {
		return fmt.Errorf("not authenticated")
	}
	
	err := m.authenticator.Renew(ctx, client)
	if err != nil {
		// Try to re-authenticate
		newClient, authErr := m.authenticator.Authenticate(ctx)
		if authErr != nil {
			return fmt.Errorf("renewal and re-authentication failed: %w", authErr)
		}
		
		m.mu.Lock()
		m.client = newClient
		m.mu.Unlock()
		
		m.logger.Info("force renewal: re-authenticated",
			"ttl", m.authenticator.GetTokenTTL())
	} else {
		m.logger.Info("force renewal: token renewed",
			"ttl", m.authenticator.GetTokenTTL())
	}
	
	return nil
}

// min returns the minimum of two durations
func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}