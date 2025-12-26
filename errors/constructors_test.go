package errors

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test input validation error constructors
func TestNewInvalidInput(t *testing.T) {
	message := "invalid data provided"
	appErr := NewInvalidInput(message)

	assert.Equal(t, ErrCodeInvalidInput, appErr.Code)
	assert.Equal(t, message, appErr.Message)
	assert.Equal(t, http.StatusBadRequest, appErr.HTTPStatus)
}

func TestNewMissingField(t *testing.T) {
	field := "username"
	appErr := NewMissingField(field)

	assert.Equal(t, ErrCodeMissingField, appErr.Code)
	assert.Contains(t, appErr.Message, field)
	assert.Equal(t, http.StatusBadRequest, appErr.HTTPStatus)
}

func TestNewInvalidFormat(t *testing.T) {
	field := "email"
	format := "valid email address"
	appErr := NewInvalidFormat(field, format)

	assert.Equal(t, ErrCodeInvalidFormat, appErr.Code)
	assert.Contains(t, appErr.Message, field)
	assert.Contains(t, appErr.Message, format)
	assert.Equal(t, http.StatusBadRequest, appErr.HTTPStatus)
}

func TestNewValueTooLong(t *testing.T) {
	field := "description"
	maxLength := 255
	appErr := NewValueTooLong(field, maxLength)

	assert.Equal(t, ErrCodeValueTooLong, appErr.Code)
	assert.Contains(t, appErr.Message, field)
	assert.Contains(t, appErr.Message, fmt.Sprintf("%d", maxLength))
	assert.Equal(t, http.StatusBadRequest, appErr.HTTPStatus)
}

func TestNewValueTooShort(t *testing.T) {
	field := "password"
	minLength := 8
	appErr := NewValueTooShort(field, minLength)

	assert.Equal(t, ErrCodeValueTooShort, appErr.Code)
	assert.Contains(t, appErr.Message, field)
	assert.Contains(t, appErr.Message, fmt.Sprintf("%d", minLength))
	assert.Equal(t, http.StatusBadRequest, appErr.HTTPStatus)
}

// Test business logic error constructors
func TestNewBusinessRule(t *testing.T) {
	message := "user cannot delete their own account"
	appErr := NewBusinessRule(message)

	assert.Equal(t, ErrCodeBusinessRule, appErr.Code)
	assert.Contains(t, appErr.Message, message)
	assert.Equal(t, http.StatusConflict, appErr.HTTPStatus)
}

func TestNewNotFound(t *testing.T) {
	resource := "user"
	appErr := NewNotFound(resource)

	assert.Equal(t, ErrCodeNotFound, appErr.Code)
	assert.Contains(t, appErr.Message, resource)
	assert.Equal(t, http.StatusNotFound, appErr.HTTPStatus)
}

func TestNewDuplicateEntry(t *testing.T) {
	resource := "email address"
	appErr := NewDuplicateEntry(resource)

	assert.Equal(t, ErrCodeDuplicateEntry, appErr.Code)
	assert.Contains(t, appErr.Message, resource)
	assert.Equal(t, http.StatusConflict, appErr.HTTPStatus)
}

// Test system error constructors
func TestNewDatabaseError(t *testing.T) {
	originalErr := errors.New("connection timeout")
	appErr := NewDatabaseError(originalErr)

	assert.Equal(t, ErrCodeDatabaseError, appErr.Code)
	assert.Equal(t, MsgFailedToExecute, appErr.Message)
	assert.Equal(t, originalErr, appErr.Err)
	assert.Equal(t, http.StatusInternalServerError, appErr.HTTPStatus)
}

func TestNewServiceUnavailable(t *testing.T) {
	service := "payment processing"
	appErr := NewServiceUnavailable(service)

	assert.Equal(t, ErrCodeServiceUnavailable, appErr.Code)
	assert.Contains(t, appErr.Message, service)
	assert.Equal(t, http.StatusServiceUnavailable, appErr.HTTPStatus)
}

func TestNewInternalError(t *testing.T) {
	originalErr := errors.New("unexpected condition")
	appErr := NewInternalError(originalErr)

	assert.Equal(t, ErrCodeInternal, appErr.Code)
	assert.Equal(t, MsgInternal, appErr.Message)
	assert.Equal(t, originalErr, appErr.Err)
	assert.Equal(t, http.StatusInternalServerError, appErr.HTTPStatus)
}

func TestNewNetworkError(t *testing.T) {
	originalErr := errors.New("host unreachable")
	appErr := NewNetworkError(originalErr)

	assert.Equal(t, ErrCodeNetworkError, appErr.Code)
	assert.Equal(t, MsgNetworkError, appErr.Message)
	assert.Equal(t, originalErr, appErr.Err)
	assert.Equal(t, http.StatusInternalServerError, appErr.HTTPStatus)
}

func TestNewTimeoutError(t *testing.T) {
	operation := "database query"
	appErr := NewTimeoutError(operation)

	assert.Equal(t, ErrCodeTimeout, appErr.Code)
	assert.Contains(t, appErr.Message, operation)
	assert.Equal(t, http.StatusInternalServerError, appErr.HTTPStatus)
}

// Test HTTP/API error constructors
func TestNewUnauthorized(t *testing.T) {
	t.Run("with custom message", func(t *testing.T) {
		message := "invalid token"
		appErr := NewUnauthorized(message)

		assert.Equal(t, ErrCodeUnauthorized, appErr.Code)
		assert.Equal(t, message, appErr.Message)
		assert.Equal(t, http.StatusUnauthorized, appErr.HTTPStatus)
	})

	t.Run("with empty message", func(t *testing.T) {
		appErr := NewUnauthorized("")

		assert.Equal(t, ErrCodeUnauthorized, appErr.Code)
		assert.Equal(t, MsgUnauthorized, appErr.Message)
		assert.Equal(t, http.StatusUnauthorized, appErr.HTTPStatus)
	})
}

func TestNewForbidden(t *testing.T) {
	t.Run("with custom message", func(t *testing.T) {
		message := "insufficient permissions"
		appErr := NewForbidden(message)

		assert.Equal(t, ErrCodeForbidden, appErr.Code)
		assert.Equal(t, message, appErr.Message)
		assert.Equal(t, http.StatusForbidden, appErr.HTTPStatus)
	})

	t.Run("with empty message", func(t *testing.T) {
		appErr := NewForbidden("")

		assert.Equal(t, ErrCodeForbidden, appErr.Code)
		assert.Equal(t, MsgForbidden, appErr.Message)
		assert.Equal(t, http.StatusForbidden, appErr.HTTPStatus)
	})
}

func TestNewRateLimitExceeded(t *testing.T) {
	t.Run("with custom message", func(t *testing.T) {
		message := "too many requests in the last hour"
		appErr := NewRateLimitExceeded(message)

		assert.Equal(t, ErrCodeRateLimit, appErr.Code)
		assert.Equal(t, message, appErr.Message)
		assert.Equal(t, http.StatusTooManyRequests, appErr.HTTPStatus)
	})

	t.Run("with empty message", func(t *testing.T) {
		appErr := NewRateLimitExceeded("")

		assert.Equal(t, ErrCodeRateLimit, appErr.Code)
		assert.Equal(t, MsgRateLimit, appErr.Message)
		assert.Equal(t, http.StatusTooManyRequests, appErr.HTTPStatus)
	})
}

// Test external service error constructors
func TestNewExternalServiceError(t *testing.T) {
	service := "payment gateway"
	originalErr := errors.New("service temporarily unavailable")
	appErr := NewExternalServiceError(service, originalErr)

	assert.Equal(t, ErrCodeExternalService, appErr.Code)
	assert.Contains(t, appErr.Message, service)
	assert.Equal(t, originalErr, appErr.Err)
	assert.Equal(t, http.StatusServiceUnavailable, appErr.HTTPStatus)
}

// Test edge cases and special scenarios
func TestConstructors_EmptyValues(t *testing.T) {
	tests := []struct {
		name        string
		constructor func() *AppError
		expectCode  ErrorCode
	}{
		{
			name:        "NewMissingField with empty field",
			constructor: func() *AppError { return NewMissingField("") },
			expectCode:  ErrCodeMissingField,
		},
		{
			name:        "NewInvalidFormat with empty field",
			constructor: func() *AppError { return NewInvalidFormat("", "") },
			expectCode:  ErrCodeInvalidFormat,
		},
		{
			name:        "NewNotFound with empty resource",
			constructor: func() *AppError { return NewNotFound("") },
			expectCode:  ErrCodeNotFound,
		},
		{
			name:        "NewServiceUnavailable with empty service",
			constructor: func() *AppError { return NewServiceUnavailable("") },
			expectCode:  ErrCodeServiceUnavailable,
		},
		{
			name:        "NewTimeoutError with empty operation",
			constructor: func() *AppError { return NewTimeoutError("") },
			expectCode:  ErrCodeTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appErr := tt.constructor()
			assert.Equal(t, tt.expectCode, appErr.Code)
			assert.NotEmpty(t, appErr.Message) // Should still have a message
		})
	}
}

func TestConstructors_NilError(t *testing.T) {
	t.Run("NewDatabaseError with nil", func(t *testing.T) {
		appErr := NewDatabaseError(nil)
		assert.Equal(t, ErrCodeDatabaseError, appErr.Code)
		assert.Nil(t, appErr.Err)
	})

	t.Run("NewInternalError with nil", func(t *testing.T) {
		appErr := NewInternalError(nil)
		assert.Equal(t, ErrCodeInternal, appErr.Code)
		assert.Nil(t, appErr.Err)
	})

	t.Run("NewNetworkError with nil", func(t *testing.T) {
		appErr := NewNetworkError(nil)
		assert.Equal(t, ErrCodeNetworkError, appErr.Code)
		assert.Nil(t, appErr.Err)
	})

	t.Run("NewExternalServiceError with nil", func(t *testing.T) {
		appErr := NewExternalServiceError("test-service", nil)
		assert.Equal(t, ErrCodeExternalService, appErr.Code)
		assert.Nil(t, appErr.Err)
	})
}

func TestConstructors_LongValues(t *testing.T) {
	longString := "This is a very long string that might exceed typical field lengths in databases or APIs. " +
		"It contains multiple sentences and should test how our error constructors handle longer input values. " +
		"We want to ensure that even with very long input, the constructors work correctly and don't cause issues."

	t.Run("NewMissingField with long field name", func(t *testing.T) {
		appErr := NewMissingField(longString)
		assert.Equal(t, ErrCodeMissingField, appErr.Code)
		assert.Contains(t, appErr.Message, longString)
	})

	t.Run("NewBusinessRule with long message", func(t *testing.T) {
		appErr := NewBusinessRule(longString)
		assert.Equal(t, ErrCodeBusinessRule, appErr.Code)
		assert.Contains(t, appErr.Message, longString)
	})
}

// Benchmark tests
func BenchmarkNewInvalidInput(b *testing.B) {
	message := "test message"

	for i := 0; i < b.N; i++ {
		_ = NewInvalidInput(message)
	}
}

func BenchmarkNewDatabaseError(b *testing.B) {
	originalErr := errors.New("database error")

	for i := 0; i < b.N; i++ {
		_ = NewDatabaseError(originalErr)
	}
}

func BenchmarkNewNotFound(b *testing.B) {
	resource := "user"

	for i := 0; i < b.N; i++ {
		_ = NewNotFound(resource)
	}
}
