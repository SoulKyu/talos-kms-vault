package validation

import (
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	// ErrInvalidUUID is returned when the UUID format is invalid
	ErrInvalidUUID = errors.New("invalid UUID format")
	
	// ErrUUIDVersionNotSupported is returned when the UUID version is not supported
	ErrUUIDVersionNotSupported = errors.New("UUID version not supported")
	
	// ErrInsufficientEntropy is returned when the UUID doesn't have enough entropy
	ErrInsufficientEntropy = errors.New("UUID has insufficient entropy")
	
	// ErrEmptyUUID is returned when the UUID is empty
	ErrEmptyUUID = errors.New("UUID cannot be empty")
	
	// ErrUUIDTooLong is returned when the UUID is too long
	ErrUUIDTooLong = errors.New("UUID too long")
)

// UUID validation patterns
var (
	// RFC 4122 UUID pattern (with or without hyphens)
	uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[1-5][0-9a-fA-F]{3}-?[89abAB][0-9a-fA-F]{3}-?[0-9a-fA-F]{12}$`)
	
	// UUID v4 specific pattern
	uuidV4Pattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?4[0-9a-fA-F]{3}-?[89abAB][0-9a-fA-F]{3}-?[0-9a-fA-F]{12}$`)
	
)

// UUIDValidator provides UUID validation functionality
type UUIDValidator struct {
	// RequireVersion4 enforces UUID v4 format
	RequireVersion4 bool
	
	// CheckEntropy performs entropy validation
	CheckEntropy bool
	
	// MinEntropyBits minimum entropy required (default: 122 bits for UUID v4)
	MinEntropyBits int
	
	// AllowHyphens allows UUIDs with hyphens
	AllowHyphens bool
	
	// MaxLength maximum allowed UUID length
	MaxLength int
}

// NewUUIDValidator creates a new UUID validator with default settings
func NewUUIDValidator() *UUIDValidator {
	return &UUIDValidator{
		RequireVersion4: true,  // Default to UUID v4 for security
		CheckEntropy:    true,  // Enable entropy checking
		MinEntropyBits:  122,   // UUID v4 has 122 bits of entropy
		AllowHyphens:    true,  // Allow standard UUID format
		MaxLength:       36,    // Standard UUID length with hyphens
	}
}

// ValidateNodeUUID validates a Talos node UUID
func (v *UUIDValidator) ValidateNodeUUID(uuid string) error {
	if uuid == "" {
		return ErrEmptyUUID
	}
	
	if len(uuid) > v.MaxLength {
		return ErrUUIDTooLong
	}
	
	// Normalize UUID (remove hyphens if not allowed)
	normalizedUUID := uuid
	if !v.AllowHyphens {
		normalizedUUID = strings.ReplaceAll(uuid, "-", "")
	}
	
	// Basic format validation
	if !v.isValidFormat(normalizedUUID) {
		return fmt.Errorf("%w: failed format check", ErrInvalidUUID)
	}
	
	// Version-specific validation
	if v.RequireVersion4 && !v.isUUIDv4(normalizedUUID) {
		return fmt.Errorf("%w: UUID v4 required", ErrUUIDVersionNotSupported)
	}
	
	// Entropy validation
	if v.CheckEntropy {
		if err := v.validateEntropy(normalizedUUID); err != nil {
			return err
		}
	}
	
	return nil
}

// isValidFormat checks if the UUID matches RFC 4122 format
func (v *UUIDValidator) isValidFormat(uuid string) bool {
	return uuidPattern.MatchString(uuid)
}

// isUUIDv4 checks if the UUID is version 4
func (v *UUIDValidator) isUUIDv4(uuid string) bool {
	return uuidV4Pattern.MatchString(uuid)
}

// validateEntropy checks if the UUID has sufficient entropy
func (v *UUIDValidator) validateEntropy(uuid string) error {
	// Remove hyphens for analysis
	cleanUUID := strings.ReplaceAll(uuid, "-", "")
	
	// Check for obviously non-random patterns
	if v.hasInsufficientEntropy(cleanUUID) {
		return fmt.Errorf("%w: UUID appears to have predictable patterns", ErrInsufficientEntropy)
	}
	
	return nil
}

// hasInsufficientEntropy performs basic entropy checks
func (v *UUIDValidator) hasInsufficientEntropy(cleanUUID string) bool {
	// Check for all zeros or all same character
	if isRepeatingPattern(cleanUUID) {
		return true
	}
	
	// Check for sequential patterns
	if hasSequentialPattern(cleanUUID) {
		return true
	}
	
	// Check for insufficient character diversity
	if hasLowCharacterDiversity(cleanUUID) {
		return true
	}
	
	return false
}

// isRepeatingPattern detects if the UUID has repeating patterns
func isRepeatingPattern(uuid string) bool {
	// Check for all same character
	if len(uuid) > 0 {
		firstChar := rune(uuid[0])
		for _, char := range uuid {
			if char != firstChar {
				return false
			}
		}
		return true
	}
	return false
}

// hasSequentialPattern detects sequential character patterns
func hasSequentialPattern(uuid string) bool {
	sequentialCount := 0
	for i := 1; i < len(uuid); i++ {
		if uuid[i] == uuid[i-1]+1 {
			sequentialCount++
		} else {
			sequentialCount = 0
		}
		
		// If we find 4+ sequential characters, consider it low entropy
		if sequentialCount >= 4 {
			return true
		}
	}
	return false
}

// hasLowCharacterDiversity checks if there are too few unique characters
func hasLowCharacterDiversity(uuid string) bool {
	uniqueChars := make(map[rune]bool)
	for _, char := range uuid {
		uniqueChars[char] = true
	}
	
	// UUID should have reasonable character diversity
	// For a 32-character hex string, we expect at least 8 different characters
	return len(uniqueChars) < 8
}

// SanitizeForLogging sanitizes a UUID for safe logging
func SanitizeForLogging(uuid string) string {
	if uuid == "" {
		return "<empty>"
	}
	
	// If it's not a valid UUID format, just show length
	if !uuidPattern.MatchString(uuid) {
		return fmt.Sprintf("<invalid-uuid-len-%d>", len(uuid))
	}
	
	// Simple approach: show first 6 chars, last 4 chars, mask the middle
	cleanUUID := strings.ReplaceAll(uuid, "-", "")
	if len(cleanUUID) >= 32 {
		// Format: 550e84**-****-****-**440000 (6 + 4 chars visible)
		return fmt.Sprintf("%s**-****-****-**%s", cleanUUID[:6], cleanUUID[28:])
	}
	
	return fmt.Sprintf("<malformed-uuid-len-%d>", len(uuid))
}

// GenerateSecureUUIDv4 generates a cryptographically secure UUID v4 for testing
func GenerateSecureUUIDv4() (string, error) {
	// Generate 16 random bytes
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	
	// Set version (4) and variant bits according to RFC 4122
	bytes[6] = (bytes[6] & 0x0f) | 0x40 // Version 4
	bytes[8] = (bytes[8] & 0x3f) | 0x80 // Variant 10
	
	// Format as UUID string
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16]), nil
}

// ValidateAndNormalize validates a UUID and returns a normalized version
func (v *UUIDValidator) ValidateAndNormalize(uuid string) (string, error) {
	if err := v.ValidateNodeUUID(uuid); err != nil {
		return "", err
	}
	
	// Normalize to lowercase with hyphens
	normalized := strings.ToLower(uuid)
	if len(strings.ReplaceAll(normalized, "-", "")) == 32 && !strings.Contains(normalized, "-") {
		// Add hyphens to plain hex string
		normalized = fmt.Sprintf("%s-%s-%s-%s-%s",
			normalized[0:8], normalized[8:12], normalized[12:16], 
			normalized[16:20], normalized[20:32])
	}
	
	return normalized, nil
}