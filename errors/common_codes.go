package errors

// Universal error codes that apply across all applications
const (
	// Validation errors - universal input validation
	ErrCodeInvalidInput  ErrorCode = "INVALID_INPUT"
	ErrCodeMissingField  ErrorCode = "MISSING_FIELD"
	ErrCodeInvalidFormat ErrorCode = "INVALID_FORMAT"
	ErrCodeValueTooLong  ErrorCode = "VALUE_TOO_LONG"
	ErrCodeValueTooShort ErrorCode = "VALUE_TOO_SHORT"

	// System/Infrastructure errors - universal system issues
	ErrCodeInternal           ErrorCode = "INTERNAL_ERROR"
	ErrCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	ErrCodeDatabaseError      ErrorCode = "DATABASE_ERROR"
	ErrCodeNetworkError       ErrorCode = "NETWORK_ERROR"
	ErrCodeTimeout            ErrorCode = "TIMEOUT"

	// HTTP/API errors - universal web service errors
	ErrCodeUnauthorized ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden    ErrorCode = "FORBIDDEN"
	ErrCodeRateLimit    ErrorCode = "RATE_LIMIT_EXCEEDED"

	// External service errors - universal integration issues
	ErrCodeExternalService ErrorCode = "EXTERNAL_SERVICE_ERROR"

	// Generic business errors - universal business concepts
	ErrCodeBusinessRule   ErrorCode = "BUSINESS_RULE_VIOLATION"
	ErrCodeDuplicateEntry ErrorCode = "DUPLICATE_ENTRY"
	ErrCodeNotFound       ErrorCode = "NOT_FOUND"
)
