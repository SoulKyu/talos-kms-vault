package validation

import (
	"context"
	"log/slog"

	"github.com/siderolabs/kms-client/api/kms"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ValidationMiddleware provides gRPC middleware for request validation
type ValidationMiddleware struct {
	validator *UUIDValidator
	logger    *slog.Logger
	
	// Metrics for validation failures (can be extended with Prometheus later)
	validationFailures int64
	validationSuccess  int64
}

// NewValidationMiddleware creates a new validation middleware
func NewValidationMiddleware(validator *UUIDValidator, logger *slog.Logger) *ValidationMiddleware {
	if validator == nil {
		validator = NewUUIDValidator()
	}
	
	if logger == nil {
		logger = slog.Default()
	}
	
	return &ValidationMiddleware{
		validator: validator,
		logger:    logger.With("component", "validation-middleware"),
	}
}

// UnaryServerInterceptor returns a gRPC unary server interceptor for validation
func (vm *ValidationMiddleware) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Only validate KMS requests
		if kmsReq, ok := req.(*kms.Request); ok {
			if err := vm.validateKMSRequest(ctx, kmsReq, info.FullMethod); err != nil {
				vm.validationFailures++
				return nil, err
			}
			vm.validationSuccess++
		}
		
		// Continue with the request
		return handler(ctx, req)
	}
}

// validateKMSRequest validates a KMS request
func (vm *ValidationMiddleware) validateKMSRequest(ctx context.Context, req *kms.Request, method string) error {
	// Validate NodeUuid
	if err := vm.validator.ValidateNodeUUID(req.NodeUuid); err != nil {
		vm.logger.WarnContext(ctx, "Invalid node UUID in request",
			"method", method,
			"node_uuid_sanitized", SanitizeForLogging(req.NodeUuid),
			"error", err.Error(),
		)
		
		return status.Error(codes.InvalidArgument, "invalid node UUID format")
	}
	
	// Validate request data constraints
	if err := vm.validateRequestData(req, method); err != nil {
		vm.logger.WarnContext(ctx, "Invalid request data",
			"method", method,
			"node_uuid_sanitized", SanitizeForLogging(req.NodeUuid),
			"error", err.Error(),
		)
		
		return err
	}
	
	// Log successful validation (debug level to avoid spam)
	vm.logger.DebugContext(ctx, "Request validation successful",
		"method", method,
		"node_uuid_sanitized", SanitizeForLogging(req.NodeUuid),
	)
	
	return nil
}

// validateRequestData validates additional request data constraints
func (vm *ValidationMiddleware) validateRequestData(req *kms.Request, method string) error {
	// Check data size limits
	const maxDataSize = 4 * 1024 * 1024 // 4MB limit
	
	if len(req.Data) > maxDataSize {
		return status.Error(codes.InvalidArgument, "request data too large")
	}
	
	// Method-specific validation
	switch method {
	case "/kms.KMSService/Seal":
		// For seal operations, ensure we have data to encrypt
		if len(req.Data) == 0 {
			return status.Error(codes.InvalidArgument, "seal operation requires data")
		}
		
	case "/kms.KMSService/Unseal":
		// For unseal operations, ensure we have ciphertext to decrypt
		if len(req.Data) == 0 {
			return status.Error(codes.InvalidArgument, "unseal operation requires ciphertext")
		}
		
		// Basic check that data looks like base64 ciphertext (should start with "vault:")
		// This is a heuristic check for Vault Transit ciphertext format
		if len(req.Data) < 6 {
			return status.Error(codes.InvalidArgument, "invalid ciphertext format")
		}
	}
	
	return nil
}

// GetValidationStats returns validation statistics
func (vm *ValidationMiddleware) GetValidationStats() (success, failures int64) {
	return vm.validationSuccess, vm.validationFailures
}

// ResetValidationStats resets validation statistics
func (vm *ValidationMiddleware) ResetValidationStats() {
	vm.validationFailures = 0
	vm.validationSuccess = 0
}

// ValidationConfig holds configuration for the validation middleware
type ValidationConfig struct {
	// Enable or disable validation
	Enabled bool
	
	// UUID validation settings
	RequireUUIDv4     bool
	CheckEntropy      bool
	MaxUUIDLength     int
	
	// Request size limits
	MaxRequestSize    int
	
	// Logging settings  
	LogSuccessfulValidation bool
	LogFailedValidation     bool
}

// DefaultValidationConfig returns default validation configuration
func DefaultValidationConfig() *ValidationConfig {
	return &ValidationConfig{
		Enabled:                 true,
		RequireUUIDv4:          true,
		CheckEntropy:           true,
		MaxUUIDLength:          36,
		MaxRequestSize:         4 * 1024 * 1024, // 4MB
		LogSuccessfulValidation: false,           // Too verbose for production
		LogFailedValidation:     true,
	}
}

// NewValidationMiddlewareFromConfig creates validation middleware from config
func NewValidationMiddlewareFromConfig(config *ValidationConfig, logger *slog.Logger) *ValidationMiddleware {
	if !config.Enabled {
		return nil
	}
	
	validator := &UUIDValidator{
		RequireVersion4: config.RequireUUIDv4,
		CheckEntropy:    config.CheckEntropy,
		AllowHyphens:    true,
		MaxLength:       config.MaxUUIDLength,
		MinEntropyBits:  122, // Standard for UUID v4
	}
	
	return NewValidationMiddleware(validator, logger)
}