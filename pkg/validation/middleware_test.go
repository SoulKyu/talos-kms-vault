package validation

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/siderolabs/kms-client/api/kms"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestValidationMiddleware_UnaryServerInterceptor(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	validator := NewUUIDValidator()
	validator.CheckEntropy = false // Disable for easier testing
	
	middleware := NewValidationMiddleware(validator, logger)
	interceptor := middleware.UnaryServerInterceptor()
	
	// Mock handler that just returns the request
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return req, nil
	}
	
	tests := []struct {
		name     string
		request  interface{}
		wantErr  bool
		wantCode codes.Code
	}{
		{
			name: "valid KMS request",
			request: &kms.Request{
				NodeUuid: "550e8400-e29b-41d4-a716-446655440000",
				Data:     []byte("test data"),
			},
			wantErr: false,
		},
		{
			name: "invalid UUID format",
			request: &kms.Request{
				NodeUuid: "invalid-uuid",
				Data:     []byte("test data"),
			},
			wantErr:  true,
			wantCode: codes.InvalidArgument,
		},
		{
			name: "empty UUID",
			request: &kms.Request{
				NodeUuid: "",
				Data:     []byte("test data"),
			},
			wantErr:  true,
			wantCode: codes.InvalidArgument,
		},
		{
			name: "UUID v1 when v4 required",
			request: &kms.Request{
				NodeUuid: "550e8400-e29b-11d4-a716-446655440000",
				Data:     []byte("test data"),
			},
			wantErr:  true,
			wantCode: codes.InvalidArgument,
		},
		{
			name: "non-KMS request (should pass through)",
			request: &struct {
				Message string
			}{
				Message: "test",
			},
			wantErr: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &grpc.UnaryServerInfo{
				FullMethod: "/kms.KMSService/Seal",
			}
			
			_, err := interceptor(context.Background(), tt.request, info, handler)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("interceptor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if tt.wantErr && tt.wantCode != codes.OK {
				st, ok := status.FromError(err)
				if !ok {
					t.Errorf("expected gRPC status error, got %v", err)
					return
				}
				
				if st.Code() != tt.wantCode {
					t.Errorf("expected status code %v, got %v", tt.wantCode, st.Code())
				}
			}
		})
	}
}

func TestValidationMiddleware_RequestDataValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	validator := NewUUIDValidator()
	validator.CheckEntropy = false // Disable for easier testing
	
	middleware := NewValidationMiddleware(validator, logger)
	
	tests := []struct {
		name     string
		request  *kms.Request
		method   string
		wantErr  bool
	}{
		{
			name: "valid seal request",
			request: &kms.Request{
				NodeUuid: "550e8400-e29b-41d4-a716-446655440000",
				Data:     []byte("test data to encrypt"),
			},
			method:  "/kms.KMSService/Seal",
			wantErr: false,
		},
		{
			name: "seal request with empty data",
			request: &kms.Request{
				NodeUuid: "550e8400-e29b-41d4-a716-446655440000",
				Data:     []byte{},
			},
			method:  "/kms.KMSService/Seal",
			wantErr: true,
		},
		{
			name: "valid unseal request",
			request: &kms.Request{
				NodeUuid: "550e8400-e29b-41d4-a716-446655440000",
				Data:     []byte("vault:v1:encrypted_data_here"),
			},
			method:  "/kms.KMSService/Unseal",
			wantErr: false,
		},
		{
			name: "unseal request with empty data",
			request: &kms.Request{
				NodeUuid: "550e8400-e29b-41d4-a716-446655440000",
				Data:     []byte{},
			},
			method:  "/kms.KMSService/Unseal",
			wantErr: true,
		},
		{
			name: "unseal request with short data",
			request: &kms.Request{
				NodeUuid: "550e8400-e29b-41d4-a716-446655440000",
				Data:     []byte("short"),
			},
			method:  "/kms.KMSService/Unseal",
			wantErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := middleware.validateKMSRequest(context.Background(), tt.request, tt.method)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("validateKMSRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidationMiddleware_Stats(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	middleware := NewValidationMiddleware(nil, logger)
	
	// Initial stats should be zero
	success, failures := middleware.GetValidationStats()
	if success != 0 || failures != 0 {
		t.Errorf("Initial stats should be zero, got success=%d, failures=%d", success, failures)
	}
	
	// Reset should work
	middleware.ResetValidationStats()
	success, failures = middleware.GetValidationStats()
	if success != 0 || failures != 0 {
		t.Errorf("After reset stats should be zero, got success=%d, failures=%d", success, failures)
	}
}

func TestDefaultValidationConfig(t *testing.T) {
	config := DefaultValidationConfig()
	
	if !config.Enabled {
		t.Error("Default config should have validation enabled")
	}
	
	if !config.RequireUUIDv4 {
		t.Error("Default config should require UUID v4")
	}
	
	if !config.CheckEntropy {
		t.Error("Default config should check entropy")
	}
	
	if config.MaxUUIDLength != 36 {
		t.Errorf("Default max UUID length should be 36, got %d", config.MaxUUIDLength)
	}
}

func TestNewValidationMiddlewareFromConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	
	// Test with disabled config
	config := &ValidationConfig{Enabled: false}
	middleware := NewValidationMiddlewareFromConfig(config, logger)
	if middleware != nil {
		t.Error("Middleware should be nil when validation is disabled")
	}
	
	// Test with enabled config
	config = DefaultValidationConfig()
	middleware = NewValidationMiddlewareFromConfig(config, logger)
	if middleware == nil {
		t.Error("Middleware should not be nil when validation is enabled")
	}
}