package validation

import (
	"fmt"
	"strings"

	"github.com/medbai2/common-go/errors"
)

// ValidationResult represents the result of validation
type ValidationResult struct {
	IsValid bool
	Errors  []ValidationError
}

// ValidationError represents a single validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// Error implements the error interface
func (ve ValidationError) Error() string {
	return fmt.Sprintf("field '%s': %s", ve.Field, ve.Message)
}

// Error implements the error interface
func (vr *ValidationResult) Error() string {
	if vr.IsValid {
		return ""
	}

	var messages []string
	for _, err := range vr.Errors {
		messages = append(messages, err.Error())
	}

	return strings.Join(messages, "; ")
}

// ToAppError converts validation result to AppError
func (vr *ValidationResult) ToAppError() *errors.AppError {
	if vr.IsValid {
		return nil
	}

	var messages []string
	for _, err := range vr.Errors {
		messages = append(messages, err.Error())
	}

	return errors.NewWithDetails(
		errors.ErrCodeInvalidInput,
		errors.MsgFailedToValidate,
		strings.Join(messages, "; "),
	)
}
