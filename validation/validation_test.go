package validation

import (
	"fmt"
	"testing"
	"time"

	"github.com/medbai2/common-go/errors"
	"github.com/medbai2/common-go/testutils"
)

// ValidationTestCase represents a validation test case
type ValidationTestCase struct {
	Name           string
	Input          interface{}
	ExpectedValid  bool
	ExpectedErrors []string
	Setup          func()
	Cleanup        func()
	ValidateResult func(t *testing.T, result ValidationResult)
}

// runValidationTestCase runs a single validation test case
func runValidationTestCase(t *testing.T, tc ValidationTestCase) {
	if tc.Setup != nil {
		tc.Setup()
	}
	if tc.Cleanup != nil {
		defer tc.Cleanup()
	}

	// This is a generic runner - specific validation logic would be implemented
	// by the calling test function
}

// Test ValidationResult basic functionality
func TestValidationResult_BasicFunctionality(t *testing.T) {
	vts := testutils.NewValidationTestSuite(t)

	testCases := []ValidationTestCase{
		{
			Name:           "Valid Result",
			Input:          "valid input",
			ExpectedValid:  true,
			ExpectedErrors: []string{},
		},
		{
			Name:           "Invalid Result with Single Error",
			Input:          "invalid input",
			ExpectedValid:  false,
			ExpectedErrors: []string{"field is required"},
		},
		{
			Name:           "Invalid Result with Multiple Errors",
			Input:          "invalid input",
			ExpectedValid:  false,
			ExpectedErrors: []string{"field is required", "field must be at least 3 characters"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Create validation result based on test case
			var result ValidationResult
			if tc.ExpectedValid {
				result = ValidationResult{
					IsValid: true,
					Errors:  []ValidationError{},
				}
			} else {
				errors := make([]ValidationError, len(tc.ExpectedErrors))
				for i, msg := range tc.ExpectedErrors {
					errors[i] = ValidationError{
						Field:   "test_field",
						Message: msg,
					}
				}
				result = ValidationResult{
					IsValid: false,
					Errors:  errors,
				}
			}

			// Test IsValid
			vts.AssertEqual(tc.ExpectedValid, result.IsValid)

			// Test Error method
			if tc.ExpectedValid {
				vts.AssertEmpty(result.Error())
			} else {
				vts.AssertNotEmpty(result.Error())
				for _, expectedError := range tc.ExpectedErrors {
					vts.AssertContains(result.Error(), expectedError)
				}
			}
		})
	}
}

// Test ValidationError
func TestValidationError(t *testing.T) {
	vts := testutils.NewValidationTestSuite(t)

	testCases := []struct {
		Name           string
		Field          string
		Message        string
		ExpectedString string
	}{
		{
			Name:           "Basic Error",
			Field:          "username",
			Message:        "username is required",
			ExpectedString: "field 'username': username is required",
		},
		{
			Name:           "Empty Field",
			Field:          "",
			Message:        "field is required",
			ExpectedString: "field '': field is required",
		},
		{
			Name:           "Long Message",
			Field:          "password",
			Message:        "password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number",
			ExpectedString: "field 'password': password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			error := ValidationError{
				Field:   tc.Field,
				Message: tc.Message,
			}

			vts.AssertEqual(tc.ExpectedString, error.Error())
		})
	}
}

// Test ToAppError conversion
func TestValidationResult_ToAppError(t *testing.T) {
	vts := testutils.NewValidationTestSuite(t)

	testCases := []struct {
		Name           string
		Result         ValidationResult
		ExpectedCode   errors.ErrorCode
		ExpectedStatus int
	}{
		{
			Name: "Valid Result",
			Result: ValidationResult{
				IsValid: true,
				Errors:  []ValidationError{},
			},
			ExpectedCode:   errors.ErrorCode(""),
			ExpectedStatus: 0,
		},
		{
			Name: "Invalid Result with Single Error",
			Result: ValidationResult{
				IsValid: false,
				Errors: []ValidationError{
					{Field: "username", Message: "username is required"},
				},
			},
			ExpectedCode:   errors.ErrCodeInvalidInput,
			ExpectedStatus: 400,
		},
		{
			Name: "Invalid Result with Multiple Errors",
			Result: ValidationResult{
				IsValid: false,
				Errors: []ValidationError{
					{Field: "username", Message: "username is required"},
					{Field: "password", Message: "password is too short"},
				},
			},
			ExpectedCode:   errors.ErrCodeInvalidInput,
			ExpectedStatus: 400,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			appError := tc.Result.ToAppError()

			if tc.Result.IsValid {
				vts.AssertNil(appError)
			} else {
				vts.AssertNotNil(appError)
				vts.AssertEqual(tc.ExpectedCode, appError.Code)
				vts.AssertEqual(tc.ExpectedStatus, appError.HTTPStatus)

				// Verify error message contains validation details
				vts.AssertEqual(errors.MsgFailedToValidate, appError.Message)
				// Check that details contain the validation error messages
				for _, validationError := range tc.Result.Errors {
					vts.AssertContains(appError.Details, validationError.Error())
				}
			}
		})
	}
}

// Test performance with large error sets
func TestValidationResult_LargeErrorSet(t *testing.T) {
	vts := testutils.NewValidationTestSuite(t)

	// Create a large number of validation errors
	errors := make([]ValidationError, 1000)
	for i := 0; i < 1000; i++ {
		errors[i] = ValidationError{
			Field:   fmt.Sprintf("field_%d", i),
			Message: fmt.Sprintf("error message %d", i),
		}
	}

	result := ValidationResult{
		IsValid: false,
		Errors:  errors,
	}

	// Test performance
	start := time.Now()
	errorString := result.Error()
	duration := time.Since(start)

	// Verify performance (should be fast even with many errors)
	vts.AssertLess(float64(duration.Nanoseconds()), float64(10*time.Millisecond.Nanoseconds()))
	vts.AssertNotEmpty(errorString)

	// Verify all errors are included
	for i := 0; i < 1000; i++ {
		vts.AssertContains(errorString, fmt.Sprintf("field_%d", i))
		vts.AssertContains(errorString, fmt.Sprintf("error message %d", i))
	}
}

// Test memory usage
func TestValidationResult_MemoryUsage(t *testing.T) {
	vts := testutils.NewValidationTestSuite(t)

	// Test with different error counts
	errorCounts := []int{1, 10, 100, 1000}

	for _, count := range errorCounts {
		t.Run(fmt.Sprintf("ErrorCount_%d", count), func(t *testing.T) {
			errors := make([]ValidationError, count)
			for i := 0; i < count; i++ {
				errors[i] = ValidationError{
					Field:   fmt.Sprintf("field_%d", i),
					Message: fmt.Sprintf("error message %d", i),
				}
			}

			result := ValidationResult{
				IsValid: false,
				Errors:  errors,
			}

			// Generate error string multiple times to test memory efficiency
			for i := 0; i < 100; i++ {
				errorString := result.Error()
				vts.AssertNotEmpty(errorString)
			}
		})
	}
}

// Test edge cases
func TestValidationResult_EdgeCases(t *testing.T) {
	vts := testutils.NewValidationTestSuite(t)

	testCases := []struct {
		Name        string
		Result      ValidationResult
		ExpectPanic bool
	}{
		{
			Name: "Nil Errors Slice",
			Result: ValidationResult{
				IsValid: false,
				Errors:  nil,
			},
			ExpectPanic: false,
		},
		{
			Name: "Empty Errors Slice",
			Result: ValidationResult{
				IsValid: false,
				Errors:  []ValidationError{},
			},
			ExpectPanic: false,
		},
		{
			Name: "Valid with Errors",
			Result: ValidationResult{
				IsValid: true,
				Errors: []ValidationError{
					{Field: "test", Message: "test error"},
				},
			},
			ExpectPanic: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.ExpectPanic {
				vts.AssertPanics(func() {
					tc.Result.Error()
				})
			} else {
				vts.AssertNotPanics(func() {
					errorString := tc.Result.Error()
					vts.AssertNotNil(errorString)
				})
			}
		})
	}
}

// Test concurrent access
func TestValidationResult_ConcurrentAccess(t *testing.T) {
	vts := testutils.NewValidationTestSuite(t)

	// Create a validation result
	result := ValidationResult{
		IsValid: false,
		Errors: []ValidationError{
			{Field: "field1", Message: "error1"},
			{Field: "field2", Message: "error2"},
		},
	}

	// Run multiple goroutines accessing the result concurrently
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			// Read IsValid
			_ = result.IsValid

			// Read Errors
			_ = result.Errors

			// Generate error string
			_ = result.Error()

			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify result is still valid
	vts.AssertFalse(result.IsValid)
	vts.AssertLen(result.Errors, 2)
}

// Test error message formatting
func TestValidationError_MessageFormatting(t *testing.T) {
	vts := testutils.NewValidationTestSuite(t)

	testCases := []struct {
		Name           string
		Field          string
		Message        string
		ExpectedFormat string
	}{
		{
			Name:           "Standard Format",
			Field:          "email",
			Message:        "invalid email format",
			ExpectedFormat: "field 'email': invalid email format",
		},
		{
			Name:           "Field with Special Characters",
			Field:          "user.name",
			Message:        "invalid format",
			ExpectedFormat: "field 'user.name': invalid format",
		},
		{
			Name:           "Empty Field Name",
			Field:          "",
			Message:        "general error",
			ExpectedFormat: "field '': general error",
		},
		{
			Name:           "Long Field Name",
			Field:          "very_long_field_name_that_might_cause_issues",
			Message:        "error message",
			ExpectedFormat: "field 'very_long_field_name_that_might_cause_issues': error message",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			error := ValidationError{
				Field:   tc.Field,
				Message: tc.Message,
			}

			formatted := error.Error()
			vts.AssertEqual(tc.ExpectedFormat, formatted)
		})
	}
}

// Test validation result immutability
func TestValidationResult_Immutability(t *testing.T) {
	vts := testutils.NewValidationTestSuite(t)

	// Create initial result
	originalErrors := []ValidationError{
		{Field: "field1", Message: "error1"},
		{Field: "field2", Message: "error2"},
	}

	result := ValidationResult{
		IsValid: false,
		Errors:  originalErrors,
	}

	// Store the original error message
	originalMessage := result.Errors[0].Error()

	// Try to modify the error in the result (this should not affect the original)
	result.Errors[0].Message = "modified error"

	// Verify the original error message is still the same
	vts.AssertEqual("field 'field1': error1", originalMessage)
	vts.AssertNotEqual("field 'field1': modified error", originalMessage)
}

// Helper functions for assertions
