package validation

import (
	"strings"
	"testing"
)

func TestUUIDValidator_ValidateNodeUUID(t *testing.T) {
	tests := []struct {
		name    string
		uuid    string
		config  *UUIDValidator
		wantErr bool
		errType error
	}{
		{
			name:    "valid UUID v4 with hyphens",
			uuid:    "550e8400-e29b-41d4-a716-446655440000",
			config:  NewUUIDValidator(),
			wantErr: false,
		},
		{
			name:    "valid UUID v4 without hyphens",
			uuid:    "550e8400e29b41d4a716446655440000",
			config:  &UUIDValidator{RequireVersion4: true, AllowHyphens: false, CheckEntropy: false, MaxLength: 32},
			wantErr: false,
		},
		{
			name:    "empty UUID",
			uuid:    "",
			config:  NewUUIDValidator(),
			wantErr: true,
			errType: ErrEmptyUUID,
		},
		{
			name:    "UUID too long",
			uuid:    "550e8400-e29b-41d4-a716-446655440000-extra",
			config:  NewUUIDValidator(),
			wantErr: true,
			errType: ErrUUIDTooLong,
		},
		{
			name:    "invalid format - not hex",
			uuid:    "550e8400-e29b-41d4-a716-44665544000g",
			config:  NewUUIDValidator(),
			wantErr: true,
			errType: ErrInvalidUUID,
		},
		{
			name:    "UUID v1 when v4 required",
			uuid:    "550e8400-e29b-11d4-a716-446655440000",
			config:  NewUUIDValidator(),
			wantErr: true,
			errType: ErrUUIDVersionNotSupported,
		},
		{
			name:    "UUID v3 when v4 required",
			uuid:    "550e8400-e29b-31d4-a716-446655440000",
			config:  NewUUIDValidator(),
			wantErr: true,
			errType: ErrUUIDVersionNotSupported,
		},
		{
			name:    "valid UUID v1 when version check disabled",
			uuid:    "550e8400-e29b-11d4-a716-446655440000",
			config:  &UUIDValidator{RequireVersion4: false, CheckEntropy: false, AllowHyphens: true, MaxLength: 36},
			wantErr: false,
		},
		{
			name:    "all zeros UUID - low entropy",
			uuid:    "00000000-0000-4000-8000-000000000000",
			config:  NewUUIDValidator(),
			wantErr: true,
			errType: ErrInsufficientEntropy,
		},
		{
			name:    "repeating pattern UUID - low entropy",
			uuid:    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			config:  NewUUIDValidator(),
			wantErr: true,
			errType: ErrInsufficientEntropy,
		},
		{
			name:    "valid UUID with entropy check disabled",
			uuid:    "00000000-0000-4000-8000-000000000000",
			config:  &UUIDValidator{RequireVersion4: true, CheckEntropy: false, AllowHyphens: true, MaxLength: 36},
			wantErr: false,
		},
		{
			name:    "malformed UUID - missing segments",
			uuid:    "550e8400-e29b-41d4-a716",
			config:  NewUUIDValidator(),
			wantErr: true,
			errType: ErrInvalidUUID,
		},
		{
			name:    "malformed UUID - wrong segment lengths",
			uuid:    "550e84-e29b-41d4-a716-446655440000",
			config:  NewUUIDValidator(),
			wantErr: true,
			errType: ErrInvalidUUID,
		},
		{
			name:    "UUID with incorrect variant bits",
			uuid:    "550e8400-e29b-41d4-1716-446655440000", // Should be 8, 9, A, or B
			config:  NewUUIDValidator(),
			wantErr: true,
			errType: ErrInvalidUUID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.ValidateNodeUUID(tt.uuid)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateNodeUUID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errType != nil {
				if !strings.Contains(err.Error(), tt.errType.Error()) {
					t.Errorf("ValidateNodeUUID() error = %v, want error containing %v", err, tt.errType)
				}
			}
		})
	}
}

func TestIsRepeatingPattern(t *testing.T) {
	tests := []struct {
		name string
		uuid string
		want bool
	}{
		{
			name: "all zeros",
			uuid: "00000000000000000000000000000000",
			want: true,
		},
		{
			name: "all same character",
			uuid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			want: true,
		},
		{
			name: "mixed characters",
			uuid: "550e8400e29b41d4a716446655440000",
			want: false,
		},
		{
			name: "empty string",
			uuid: "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRepeatingPattern(tt.uuid); got != tt.want {
				t.Errorf("isRepeatingPattern() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasSequentialPattern(t *testing.T) {
	tests := []struct {
		name string
		uuid string
		want bool
	}{
		{
			name: "sequential pattern",
			uuid: "12345678e29b41d4a716446655440000",
			want: true,
		},
		{
			name: "no sequential pattern",
			uuid: "550e8400e29b41d4a716446655440000",
			want: false,
		},
		{
			name: "short sequential pattern (allowed)",
			uuid: "123a8400e29b41d4a716446655440000",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasSequentialPattern(tt.uuid); got != tt.want {
				t.Errorf("hasSequentialPattern() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasLowCharacterDiversity(t *testing.T) {
	tests := []struct {
		name string
		uuid string
		want bool
	}{
		{
			name: "low diversity - only 2 characters",
			uuid: "00000000111111111111111111111111",
			want: true,
		},
		{
			name: "good diversity",
			uuid: "0123456789abcdef0123456789abcdef",
			want: false,
		},
		{
			name: "borderline diversity - 7 characters",
			uuid: "01234560123456012345601234560123",
			want: true,
		},
		{
			name: "sufficient diversity - 8 characters",
			uuid: "01234567012345670123456701234567",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasLowCharacterDiversity(tt.uuid); got != tt.want {
				t.Errorf("hasLowCharacterDiversity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeForLogging(t *testing.T) {
	tests := []struct {
		name string
		uuid string
		want string
	}{
		{
			name: "valid UUID with hyphens",
			uuid: "550e8400-e29b-41d4-a716-446655440000",
			want: "550e84**-****-****-**0000",
		},
		{
			name: "valid UUID without hyphens",
			uuid: "550e8400e29b41d4a716446655440000",
			want: "550e84**-****-****-**0000",
		},
		{
			name: "empty UUID",
			uuid: "",
			want: "<empty>",
		},
		{
			name: "invalid UUID",
			uuid: "not-a-uuid",
			want: "<invalid-uuid-len-10>",
		},
		{
			name: "malformed UUID",
			uuid: "550e8400-e29b-41d4-a716",
			want: "<invalid-uuid-len-23>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeForLogging(tt.uuid); got != tt.want {
				t.Errorf("SanitizeForLogging() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateAndNormalize(t *testing.T) {
	validator := NewUUIDValidator()
	validator.CheckEntropy = false // Disable for testing

	tests := []struct {
		name    string
		uuid    string
		want    string
		wantErr bool
	}{
		{
			name:    "uppercase UUID with hyphens",
			uuid:    "550E8400-E29B-41D4-A716-446655440000",
			want:    "550e8400-e29b-41d4-a716-446655440000",
			wantErr: false,
		},
		{
			name:    "lowercase UUID without hyphens",
			uuid:    "550e8400e29b41d4a716446655440000",
			want:    "550e8400-e29b-41d4-a716-446655440000",
			wantErr: false,
		},
		{
			name:    "mixed case with hyphens",
			uuid:    "550e8400-E29B-41d4-A716-446655440000",
			want:    "550e8400-e29b-41d4-a716-446655440000",
			wantErr: false,
		},
		{
			name:    "invalid UUID",
			uuid:    "invalid-uuid",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validator.ValidateAndNormalize(tt.uuid)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAndNormalize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateAndNormalize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateSecureUUIDv4(t *testing.T) {
	validator := NewUUIDValidator()

	// Generate multiple UUIDs to test uniqueness and format
	uuids := make(map[string]bool)

	for i := 0; i < 10; i++ {
		uuid, err := GenerateSecureUUIDv4()
		if err != nil {
			t.Fatalf("GenerateSecureUUIDv4() error = %v", err)
		}

		// Check if UUID is unique
		if uuids[uuid] {
			t.Errorf("GenerateSecureUUIDv4() generated duplicate UUID: %s", uuid)
		}
		uuids[uuid] = true

		// Validate the generated UUID
		if err := validator.ValidateNodeUUID(uuid); err != nil {
			t.Errorf("Generated UUID %s failed validation: %v", uuid, err)
		}

		// Check UUID v4 format specifically
		if !validator.isUUIDv4(uuid) {
			t.Errorf("Generated UUID %s is not valid UUID v4 format", uuid)
		}
	}
}

func TestUUIDValidator_Configuration(t *testing.T) {
	tests := []struct {
		name      string
		config    *UUIDValidator
		uuid      string
		wantErr   bool
		errSubstr string
	}{
		{
			name: "strict v4 validation",
			config: &UUIDValidator{
				RequireVersion4: true,
				CheckEntropy:    false,
				AllowHyphens:    true,
				MaxLength:       36,
			},
			uuid:      "550e8400-e29b-11d4-a716-446655440000", // UUID v1
			wantErr:   true,
			errSubstr: "version not supported",
		},
		{
			name: "permissive validation",
			config: &UUIDValidator{
				RequireVersion4: false,
				CheckEntropy:    false,
				AllowHyphens:    true,
				MaxLength:       36,
			},
			uuid:    "550e8400-e29b-11d4-a716-446655440000", // UUID v1
			wantErr: false,
		},
		{
			name: "no hyphens allowed - should pass length check first",
			config: &UUIDValidator{
				RequireVersion4: true,
				CheckEntropy:    false,
				AllowHyphens:    false,
				MaxLength:       32,
			},
			uuid:      "550e8400-e29b-41d4-a716-446655440000",
			wantErr:   true,
			errSubstr: "too long", // Length check happens first
		},
		{
			name: "short max length",
			config: &UUIDValidator{
				RequireVersion4: false,
				CheckEntropy:    false,
				AllowHyphens:    true,
				MaxLength:       20,
			},
			uuid:      "550e8400-e29b-41d4-a716-446655440000",
			wantErr:   true,
			errSubstr: "too long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.ValidateNodeUUID(tt.uuid)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateNodeUUID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("ValidateNodeUUID() error = %v, want substring %v", err, tt.errSubstr)
			}
		})
	}
}

// Benchmark tests for performance
func BenchmarkValidateNodeUUID(b *testing.B) {
	validator := NewUUIDValidator()
	uuid := "550e8400-e29b-41d4-a716-446655440000"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.ValidateNodeUUID(uuid)
	}
}

func BenchmarkSanitizeForLogging(b *testing.B) {
	uuid := "550e8400-e29b-41d4-a716-446655440000"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SanitizeForLogging(uuid)
	}
}
