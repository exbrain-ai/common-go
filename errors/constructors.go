package errors

import "fmt"

// Common error constructors for frequently used errors across all applications

// Input validation errors
func NewInvalidInput(message string) *AppError {
	return New(ErrCodeInvalidInput, message)
}

func NewMissingField(field string) *AppError {
	return New(ErrCodeMissingField, GetMessage(ErrCodeMissingField, field))
}

func NewInvalidFormat(field, format string) *AppError {
	return New(ErrCodeInvalidFormat, GetMessage(ErrCodeInvalidFormat, fmt.Sprintf("field '%s': expected %s", field, format)))
}

func NewValueTooLong(field string, maxLength int) *AppError {
	return New(ErrCodeValueTooLong, GetMessage(ErrCodeValueTooLong, fmt.Sprintf("field '%s': max %d characters", field, maxLength)))
}

func NewValueTooShort(field string, minLength int) *AppError {
	return New(ErrCodeValueTooShort, GetMessage(ErrCodeValueTooShort, fmt.Sprintf("field '%s': min %d characters", field, minLength)))
}

// Business logic errors
func NewBusinessRule(message string) *AppError {
	return New(ErrCodeBusinessRule, GetMessage(ErrCodeBusinessRule, message))
}

func NewNotFound(resource string) *AppError {
	return New(ErrCodeNotFound, GetMessage(ErrCodeNotFound, resource))
}

func NewDuplicateEntry(resource string) *AppError {
	return New(ErrCodeDuplicateEntry, GetMessage(ErrCodeDuplicateEntry, resource))
}

// System errors
func NewDatabaseError(err error) *AppError {
	return Wrap(err, ErrCodeDatabaseError, MsgFailedToExecute)
}

func NewServiceUnavailable(service string) *AppError {
	return New(ErrCodeServiceUnavailable, GetMessage(ErrCodeServiceUnavailable, service))
}

func NewInternalError(err error) *AppError {
	return Wrap(err, ErrCodeInternal, MsgInternal)
}

func NewNetworkError(err error) *AppError {
	return Wrap(err, ErrCodeNetworkError, MsgNetworkError)
}

func NewTimeoutError(operation string) *AppError {
	return New(ErrCodeTimeout, GetMessage(ErrCodeTimeout, operation))
}

// HTTP/API errors
func NewUnauthorized(message string) *AppError {
	if message == "" {
		message = MsgUnauthorized
	}
	return New(ErrCodeUnauthorized, message)
}

func NewForbidden(message string) *AppError {
	if message == "" {
		message = MsgForbidden
	}
	return New(ErrCodeForbidden, message)
}

func NewRateLimitExceeded(message string) *AppError {
	if message == "" {
		message = MsgRateLimit
	}
	return New(ErrCodeRateLimit, message)
}

// External service errors
func NewExternalServiceError(service string, err error) *AppError {
	return Wrap(err, ErrCodeExternalService, GetMessage(ErrCodeExternalService, service))
}

