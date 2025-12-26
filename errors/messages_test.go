package errors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test message constants
func TestMessageConstants(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		expected string
	}{
		{"MsgInvalidInput", MsgInvalidInput, "invalid input provided"},
		{"MsgMissingField", MsgMissingField, "missing required field"},
		{"MsgInvalidFormat", MsgInvalidFormat, "invalid format"},
		{"MsgValueTooLong", MsgValueTooLong, "value exceeds maximum length"},
		{"MsgValueTooShort", MsgValueTooShort, "value is too short"},
		{"MsgInternal", MsgInternal, "internal server error"},
		{"MsgServiceUnavailable", MsgServiceUnavailable, "service temporarily unavailable"},
		{"MsgDatabaseError", MsgDatabaseError, "database operation failed"},
		{"MsgNetworkError", MsgNetworkError, "network operation failed"},
		{"MsgTimeout", MsgTimeout, "operation timed out"},
		{"MsgUnauthorized", MsgUnauthorized, "unauthorized access"},
		{"MsgForbidden", MsgForbidden, "access forbidden"},
		{"MsgRateLimit", MsgRateLimit, "rate limit exceeded"},
		{"MsgExternalService", MsgExternalService, "external service error"},
		{"MsgBusinessRule", MsgBusinessRule, "business rule violation"},
		{"MsgDuplicateEntry", MsgDuplicateEntry, "entry already exists"},
		{"MsgNotFound", MsgNotFound, "resource not found"},
		{"MsgFailedToConnect", MsgFailedToConnect, "failed to connect"},
		{"MsgFailedToExecute", MsgFailedToExecute, "failed to execute operation"},
		{"MsgConfigurationError", MsgConfigurationError, "configuration error"},
		{"MsgFailedToValidate", MsgFailedToValidate, "validation failed"},
		{"MsgFailedToSanitize", MsgFailedToSanitize, "sanitization failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.message)
			assert.NotEmpty(t, tt.message, "Message constant should not be empty")
		})
	}
}

// Test GetMessage function
func TestGetMessage_WithoutContext(t *testing.T) {
	tests := []struct {
		name     string
		code     ErrorCode
		expected string
	}{
		{"InvalidInput", ErrCodeInvalidInput, MsgInvalidInput},
		{"MissingField", ErrCodeMissingField, MsgMissingField},
		{"InvalidFormat", ErrCodeInvalidFormat, MsgInvalidFormat},
		{"ValueTooLong", ErrCodeValueTooLong, MsgValueTooLong},
		{"ValueTooShort", ErrCodeValueTooShort, MsgValueTooShort},
		{"BusinessRule", ErrCodeBusinessRule, MsgBusinessRule},
		{"DuplicateEntry", ErrCodeDuplicateEntry, MsgDuplicateEntry},
		{"NotFound", ErrCodeNotFound, MsgNotFound},
		{"Unauthorized", ErrCodeUnauthorized, MsgUnauthorized},
		{"Forbidden", ErrCodeForbidden, MsgForbidden},
		{"Internal", ErrCodeInternal, MsgInternal},
		{"ServiceUnavailable", ErrCodeServiceUnavailable, MsgServiceUnavailable},
		{"DatabaseError", ErrCodeDatabaseError, MsgDatabaseError},
		{"NetworkError", ErrCodeNetworkError, MsgNetworkError},
		{"Timeout", ErrCodeTimeout, MsgTimeout},
		{"ExternalService", ErrCodeExternalService, MsgExternalService},
		{"RateLimit", ErrCodeRateLimit, MsgRateLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetMessage(tt.code)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetMessage_WithContext(t *testing.T) {
	tests := []struct {
		name     string
		code     ErrorCode
		context  string
		expected string
	}{
		{
			"InvalidInput with context",
			ErrCodeInvalidInput,
			"email format is incorrect",
			MsgInvalidInput + ": email format is incorrect",
		},
		{
			"MissingField with context",
			ErrCodeMissingField,
			"username field",
			MsgMissingField + ": username field",
		},
		{
			"DatabaseError with context",
			ErrCodeDatabaseError,
			"connection timeout",
			MsgDatabaseError + ": connection timeout",
		},
		{
			"NotFound with context",
			ErrCodeNotFound,
			"user with ID 123",
			MsgNotFound + ": user with ID 123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetMessage(tt.code, tt.context)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetMessage_UnknownCode(t *testing.T) {
	unknownCode := ErrorCode("UNKNOWN_CODE")
	result := GetMessage(unknownCode)
	assert.Equal(t, MsgInternal, result)
}

func TestGetMessage_UnknownCodeWithContext(t *testing.T) {
	unknownCode := ErrorCode("UNKNOWN_CODE")
	context := "some additional info"
	result := GetMessage(unknownCode, context)
	assert.Equal(t, MsgInternal+": "+context, result)
}

func TestGetMessage_EmptyContext(t *testing.T) {
	result := GetMessage(ErrCodeInvalidInput, "")
	expected := MsgInvalidInput + ": "
	assert.Equal(t, expected, result)
}

func TestGetMessage_MultipleContexts(t *testing.T) {
	// Only the first context should be used
	result := GetMessage(ErrCodeInvalidInput, "first context", "second context", "third context")
	expected := MsgInvalidInput + ": first context"
	assert.Equal(t, expected, result)
}

// Test getBaseMessage function
func TestGetBaseMessage(t *testing.T) {
	tests := []struct {
		name     string
		code     ErrorCode
		expected string
	}{
		{"ValidCode", ErrCodeInvalidInput, MsgInvalidInput},
		{"UnknownCode", ErrorCode("INVALID_CODE"), MsgInternal},
		{"EmptyCode", ErrorCode(""), MsgInternal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getBaseMessage(tt.code)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test message consistency
func TestMessageConsistency(t *testing.T) {
	// Test that all messages are consistent in style
	messages := []string{
		MsgInvalidInput,
		MsgMissingField,
		MsgInvalidFormat,
		MsgValueTooLong,
		MsgValueTooShort,
		MsgInternal,
		MsgServiceUnavailable,
		MsgDatabaseError,
		MsgNetworkError,
		MsgTimeout,
		MsgUnauthorized,
		MsgForbidden,
		MsgRateLimit,
		MsgExternalService,
		MsgBusinessRule,
		MsgDuplicateEntry,
		MsgNotFound,
		MsgFailedToConnect,
		MsgFailedToExecute,
		MsgConfigurationError,
		MsgFailedToValidate,
		MsgFailedToSanitize,
	}

	for _, msg := range messages {
		// All messages should be lowercase and not end with punctuation
		assert.NotEmpty(t, msg, "Message should not be empty")
		assert.Equal(t, msg, msg, "Message should be consistent")

		// Messages should not start with uppercase (consistent style)
		if len(msg) > 0 {
			firstChar := msg[0]
			assert.True(t, firstChar >= 'a' && firstChar <= 'z',
				"Message should start with lowercase letter: %s", msg)
		}

		// Messages should not end with punctuation
		if len(msg) > 0 {
			lastChar := msg[len(msg)-1]
			assert.NotEqual(t, '.', lastChar, "Message should not end with period: %s", msg)
			assert.NotEqual(t, '!', lastChar, "Message should not end with exclamation: %s", msg)
		}
	}
}

// Test message length constraints (reasonable limits)
func TestMessageLength(t *testing.T) {
	messages := []string{
		MsgInvalidInput,
		MsgMissingField,
		MsgInvalidFormat,
		MsgValueTooLong,
		MsgValueTooShort,
		MsgInternal,
		MsgServiceUnavailable,
		MsgDatabaseError,
		MsgNetworkError,
		MsgTimeout,
		MsgUnauthorized,
		MsgForbidden,
		MsgRateLimit,
		MsgExternalService,
		MsgBusinessRule,
		MsgDuplicateEntry,
		MsgNotFound,
		MsgFailedToConnect,
		MsgFailedToExecute,
		MsgConfigurationError,
		MsgFailedToValidate,
		MsgFailedToSanitize,
	}

	for _, msg := range messages {
		assert.GreaterOrEqual(t, len(msg), 5, "Message should be at least 5 characters: %s", msg)
		assert.LessOrEqual(t, len(msg), 50, "Message should be at most 50 characters: %s", msg)
	}
}

// Benchmark tests
func BenchmarkGetMessage(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GetMessage(ErrCodeInvalidInput)
	}
}

func BenchmarkGetMessageWithContext(b *testing.B) {
	context := "test context"

	for i := 0; i < b.N; i++ {
		_ = GetMessage(ErrCodeInvalidInput, context)
	}
}

func BenchmarkGetBaseMessage(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = getBaseMessage(ErrCodeInvalidInput)
	}
}
