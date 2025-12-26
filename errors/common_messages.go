package errors

// Universal error message constants to prevent hardcoded strings
const (
	// Validation error messages
	MsgInvalidInput  = "invalid input provided"
	MsgMissingField  = "missing required field"
	MsgInvalidFormat = "invalid format"
	MsgValueTooLong  = "value exceeds maximum length"
	MsgValueTooShort = "value is too short"

	// System error messages
	MsgInternal           = "internal server error"
	MsgServiceUnavailable = "service temporarily unavailable"
	MsgDatabaseError      = "database operation failed"
	MsgNetworkError       = "network operation failed"
	MsgTimeout            = "operation timed out"

	// HTTP/API error messages
	MsgUnauthorized = "unauthorized access"
	MsgForbidden    = "access forbidden"
	MsgRateLimit    = "rate limit exceeded"

	// External service error messages
	MsgExternalService = "external service error"

	// Generic business error messages
	MsgBusinessRule   = "business rule violation"
	MsgDuplicateEntry = "entry already exists"
	MsgNotFound       = "resource not found"

	// Common operation messages
	MsgFailedToConnect    = "failed to connect"
	MsgFailedToExecute    = "failed to execute operation"
	MsgConfigurationError = "configuration error"
	MsgFailedToValidate   = "validation failed"
	MsgFailedToSanitize   = "sanitization failed"
)

// GetMessage returns a formatted error message
func GetMessage(code ErrorCode, context ...string) string {
	baseMessage := getBaseMessage(code)
	if len(context) > 0 {
		return baseMessage + ": " + context[0]
	}
	return baseMessage
}

// getBaseMessage returns the base message for an error code
func getBaseMessage(code ErrorCode) string {
	switch code {
	case ErrCodeInvalidInput:
		return MsgInvalidInput
	case ErrCodeMissingField:
		return MsgMissingField
	case ErrCodeInvalidFormat:
		return MsgInvalidFormat
	case ErrCodeValueTooLong:
		return MsgValueTooLong
	case ErrCodeValueTooShort:
		return MsgValueTooShort
	case ErrCodeBusinessRule:
		return MsgBusinessRule
	case ErrCodeDuplicateEntry:
		return MsgDuplicateEntry
	case ErrCodeNotFound:
		return MsgNotFound
	case ErrCodeUnauthorized:
		return MsgUnauthorized
	case ErrCodeForbidden:
		return MsgForbidden
	case ErrCodeInternal:
		return MsgInternal
	case ErrCodeServiceUnavailable:
		return MsgServiceUnavailable
	case ErrCodeDatabaseError:
		return MsgDatabaseError
	case ErrCodeNetworkError:
		return MsgNetworkError
	case ErrCodeTimeout:
		return MsgTimeout
	case ErrCodeExternalService:
		return MsgExternalService
	case ErrCodeRateLimit:
		return MsgRateLimit
	default:
		return MsgInternal
	}
}

