package auth

import (
	"errors"
	"fmt"
)

var (
	// ErrUnsupportedAuthMethod is returned when an unsupported auth method is requested
	ErrUnsupportedAuthMethod = errors.New("unsupported authentication method")
	
	// ErrAuthenticationFailed is returned when authentication fails
	ErrAuthenticationFailed = errors.New("authentication failed")
	
	// ErrTokenRenewalFailed is returned when token renewal fails
	ErrTokenRenewalFailed = errors.New("token renewal failed")
	
	// ErrTokenRevocationFailed is returned when token revocation fails
	ErrTokenRevocationFailed = errors.New("token revocation failed")
	
	// ErrMissingConfiguration is returned when required configuration is missing
	ErrMissingConfiguration = errors.New("missing required configuration")
	
	// ErrTokenExpired is returned when the token has expired
	ErrTokenExpired = errors.New("token has expired")
	
	// ErrNoAuthMethod is returned when no auth method can be determined
	ErrNoAuthMethod = errors.New("no authentication method available")
)

// AuthError wraps authentication-related errors with additional context
type AuthError struct {
	Method  AuthMethod
	Op      string
	Err     error
	Message string
}

// Error implements the error interface
func (e *AuthError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("auth %s [%s]: %s: %v", e.Method, e.Op, e.Message, e.Err)
	}
	return fmt.Sprintf("auth %s [%s]: %v", e.Method, e.Op, e.Err)
}

// Unwrap returns the underlying error
func (e *AuthError) Unwrap() error {
	return e.Err
}

// NewAuthError creates a new AuthError
func NewAuthError(method AuthMethod, op string, err error, message string) *AuthError {
	return &AuthError{
		Method:  method,
		Op:      op,
		Err:     err,
		Message: message,
	}
}