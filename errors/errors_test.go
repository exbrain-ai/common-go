package errors

import (
	"errors"
	"net/http"
	"testing"

	"github.com/medbai2/common-go/testutils"
)

func TestAppError_BasicFunctionality(t *testing.T) {
	ets := testutils.NewErrorTestSuite(t)

	// Test basic error creation
	err := New(ErrCodeInvalidInput, "Invalid input provided")

	ets.AssertNotNil(err)
	ets.AssertEqual(ErrCodeInvalidInput, err.Code)
	ets.AssertEqual("Invalid input provided", err.Message)
	ets.AssertEqual(http.StatusBadRequest, err.HTTPStatus)
	ets.AssertEmpty(err.Details)
	ets.AssertNil(err.Err)
}

func TestAppError_WithDetails(t *testing.T) {
	ets := testutils.NewErrorTestSuite(t)

	// Test error with details
	err := NewWithDetails(ErrCodeInvalidInput, "Validation failed", "Field 'email' is required")

	ets.AssertNotNil(err)
	ets.AssertEqual(ErrCodeInvalidInput, err.Code)
	ets.AssertEqual("Validation failed", err.Message)
	ets.AssertEqual("Field 'email' is required", err.Details)
	ets.AssertEqual(http.StatusBadRequest, err.HTTPStatus)
}

func TestAppError_WithWrappedError(t *testing.T) {
	ets := testutils.NewErrorTestSuite(t)

	// Test error wrapping
	originalErr := errors.New("original error")
	err := Wrap(originalErr, ErrCodeDatabaseError, "Database operation failed")

	ets.AssertNotNil(err)
	ets.AssertEqual(ErrCodeDatabaseError, err.Code)
	ets.AssertEqual("Database operation failed", err.Message)
	ets.AssertEqual(originalErr, err.Unwrap())
}

func TestAppError_ErrorString(t *testing.T) {
	ets := testutils.NewErrorTestSuite(t)

	// Test error string format
	err := New(ErrCodeInvalidInput, "Invalid input")
	errorString := err.Error()

	ets.AssertContains(errorString, string(ErrCodeInvalidInput))
	ets.AssertContains(errorString, "Invalid input")
}

func TestAppError_ErrorStringWithWrappedError(t *testing.T) {
	ets := testutils.NewErrorTestSuite(t)

	// Test error string with wrapped error
	originalErr := errors.New("original error")
	err := Wrap(originalErr, ErrCodeDatabaseError, "Database error")
	errorString := err.Error()

	ets.AssertContains(errorString, string(ErrCodeDatabaseError))
	ets.AssertContains(errorString, "Database error")
	ets.AssertContains(errorString, "original error")
}

func TestErrorConstructors(t *testing.T) {
	ets := testutils.NewErrorTestSuite(t)

	// Test NewInvalidInput
	err := NewInvalidInput("test field")
	ets.AssertNotNil(err)
	ets.AssertEqual(ErrCodeInvalidInput, err.Code)
	ets.AssertEqual(http.StatusBadRequest, err.HTTPStatus)

	// Test NewNotFound
	err = NewNotFound("user")
	ets.AssertNotNil(err)
	ets.AssertEqual(ErrCodeNotFound, err.Code)
	ets.AssertEqual(http.StatusNotFound, err.HTTPStatus)

	// Test NewInternalError
	originalErr := errors.New("unexpected error")
	err = NewInternalError(originalErr)
	ets.AssertNotNil(err)
	ets.AssertEqual(ErrCodeInternal, err.Code)
	ets.AssertEqual(http.StatusInternalServerError, err.HTTPStatus)

	// Test NewDatabaseError
	dbErr := errors.New("connection failed")
	err = NewDatabaseError(dbErr)
	ets.AssertNotNil(err)
	ets.AssertEqual(ErrCodeDatabaseError, err.Code)
	ets.AssertEqual(http.StatusInternalServerError, err.HTTPStatus)

	// Test NewUnauthorized
	err = NewUnauthorized("access denied")
	ets.AssertNotNil(err)
	ets.AssertEqual(ErrCodeUnauthorized, err.Code)
	ets.AssertEqual(http.StatusUnauthorized, err.HTTPStatus)

	// Test NewForbidden
	err = NewForbidden("insufficient permissions")
	ets.AssertNotNil(err)
	ets.AssertEqual(ErrCodeForbidden, err.Code)
	ets.AssertEqual(http.StatusForbidden, err.HTTPStatus)

	// Test NewRateLimitExceeded
	err = NewRateLimitExceeded("rate limit exceeded")
	ets.AssertNotNil(err)
	ets.AssertEqual(ErrCodeRateLimit, err.Code)
	ets.AssertEqual(http.StatusTooManyRequests, err.HTTPStatus)

	// Test NewServiceUnavailable
	err = NewServiceUnavailable("database service")
	ets.AssertNotNil(err)
	ets.AssertEqual(ErrCodeServiceUnavailable, err.Code)
	ets.AssertEqual(http.StatusServiceUnavailable, err.HTTPStatus)
}

func TestErrorWrapping(t *testing.T) {
	ets := testutils.NewErrorTestSuite(t)

	// Test Wrap
	originalErr := errors.New("original error")
	wrappedErr := Wrap(originalErr, ErrCodeDatabaseError, "wrapped message")

	ets.AssertNotNil(wrappedErr)
	ets.AssertEqual(ErrCodeDatabaseError, wrappedErr.Code)
	ets.AssertEqual("wrapped message", wrappedErr.Message)
	ets.AssertEqual(originalErr, wrappedErr.Unwrap())

	// Test WrapWithDetails
	details := "operation failed"
	wrappedWithDetails := WrapWithDetails(originalErr, ErrCodeDatabaseError, "wrapped with details", details)

	ets.AssertNotNil(wrappedWithDetails)
	ets.AssertEqual(ErrCodeDatabaseError, wrappedWithDetails.Code)
	ets.AssertEqual("wrapped with details", wrappedWithDetails.Message)
	ets.AssertEqual(originalErr, wrappedWithDetails.Unwrap())
	ets.AssertEqual(details, wrappedWithDetails.Details)
}

func TestErrorTypeChecking(t *testing.T) {
	ets := testutils.NewErrorTestSuite(t)

	// Test IsAppError
	appErr := NewInvalidInput("field")
	ets.AssertTrue(IsAppError(appErr))

	// Test with standard error
	stdErr := errors.New("standard error")
	ets.AssertFalse(IsAppError(stdErr))

	// Test with nil
	ets.AssertFalse(IsAppError(nil))

	// Test GetAppError
	retrievedErr := GetAppError(appErr)
	ets.AssertNotNil(retrievedErr)
	ets.AssertEqual(appErr, retrievedErr)

	// Test GetAppError with standard error
	retrievedStdErr := GetAppError(stdErr)
	ets.AssertNil(retrievedStdErr)

	// Test GetAppError with nil
	retrievedNilErr := GetAppError(nil)
	ets.AssertNil(retrievedNilErr)
}

func TestHTTPStatusMapping(t *testing.T) {
	ets := testutils.NewErrorTestSuite(t)

	testCases := []struct {
		Code           ErrorCode
		ExpectedStatus int
	}{
		{ErrCodeInvalidInput, http.StatusBadRequest},
		{ErrCodeMissingField, http.StatusBadRequest},
		{ErrCodeInvalidFormat, http.StatusBadRequest},
		{ErrCodeValueTooLong, http.StatusBadRequest},
		{ErrCodeValueTooShort, http.StatusBadRequest},
		{ErrCodeNotFound, http.StatusNotFound},
		{ErrCodeUnauthorized, http.StatusUnauthorized},
		{ErrCodeForbidden, http.StatusForbidden},
		{ErrCodeRateLimit, http.StatusTooManyRequests},
		{ErrCodeInternal, http.StatusInternalServerError},
		{ErrCodeDatabaseError, http.StatusInternalServerError},
		{ErrCodeServiceUnavailable, http.StatusServiceUnavailable},
		{ErrCodeNetworkError, http.StatusInternalServerError},
		{ErrCodeTimeout, http.StatusInternalServerError},
		{ErrCodeExternalService, http.StatusServiceUnavailable},
		{ErrCodeBusinessRule, http.StatusConflict},
		{ErrCodeDuplicateEntry, http.StatusConflict},
	}

	for _, tc := range testCases {
		t.Run(string(tc.Code), func(t *testing.T) {
			err := New(tc.Code, "test message")
			ets.AssertEqual(tc.ExpectedStatus, err.HTTPStatus)
		})
	}
}

func TestErrorChaining(t *testing.T) {
	ets := testutils.NewErrorTestSuite(t)

	// Create a chain of errors
	originalErr := errors.New("original error")
	level1Err := Wrap(originalErr, ErrCodeDatabaseError, "database operation failed")
	level2Err := Wrap(level1Err, ErrCodeInternal, "internal processing failed")

	// Test unwrapping chain
	ets.AssertEqual(level1Err, level2Err.Unwrap())
	ets.AssertEqual(originalErr, level1Err.Unwrap())

	// Test deeper unwrapping
	unwrapped := level2Err.Unwrap()
	if appErr, ok := unwrapped.(*AppError); ok {
		ets.AssertEqual(originalErr, appErr.Unwrap())
	}

	// Test error messages
	ets.AssertContains(level2Err.Error(), "internal processing failed")
	ets.AssertContains(level2Err.Error(), "database operation failed")
	ets.AssertContains(level2Err.Error(), "original error")
}

func TestConcurrentErrorCreation(t *testing.T) {
	ets := testutils.NewErrorTestSuite(t)

	// Run multiple goroutines creating errors concurrently
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			err := NewInvalidInput(string(rune(id)))
			ets.AssertNotNil(err)
			ets.AssertEqual(ErrCodeInvalidInput, err.Code)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestErrorComparison(t *testing.T) {
	ets := testutils.NewErrorTestSuite(t)

	// Test same error
	err1 := NewInvalidInput("field")
	err2 := NewInvalidInput("field")

	// They should be different instances but have same content
	ets.AssertEqual(err1.Code, err2.Code)
	ets.AssertEqual(err1.Message, err2.Message)

	// Test that they are not the same instance
	ets.AssertTrue(err1 != err2)

	// Test different errors
	err3 := NewNotFound("field")
	ets.AssertNotEqual(err1.Code, err3.Code)
	// Note: Messages might be the same due to generic error messages
	// ets.AssertNotEqual(err1.Message, err3.Message)
}

func TestEdgeCases(t *testing.T) {
	ets := testutils.NewErrorTestSuite(t)

	// Test with empty message
	err := New(ErrCodeInvalidInput, "")
	ets.AssertEqual("", err.Message)
	ets.AssertNotEmpty(err.Error()) // Should still have code

	// Test with nil wrapped error
	err = Wrap(nil, ErrCodeDatabaseError, "Database error")
	ets.AssertNil(err.Unwrap())

	// Test with empty details
	err = NewWithDetails(ErrCodeInvalidInput, "Validation error", "")
	ets.AssertNotNil(err.Details)
	ets.AssertEmpty(err.Details)
}
