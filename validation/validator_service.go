package validation

import (
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
)

// ValidatorService provides enterprise-grade validation using go-playground/validator
type ValidatorService struct {
	validator *validator.Validate
}

// NewValidatorService creates a new validator service with enterprise configuration
func NewValidatorService() *ValidatorService {
	v := validator.New()

	// Register custom validators for enterprise use
	v.RegisterValidation("alphanumspace", validateAlphaNumSpace)
	v.RegisterValidation("companyname", validateCompanyName)
	v.RegisterValidation("ssn", validateSSN)
	v.RegisterValidation("phone", validatePhone)

	return &ValidatorService{
		validator: v,
	}
}

// ValidateStruct validates a struct using go-playground/validator
func (vs *ValidatorService) ValidateStruct(s interface{}) *ValidationResult {
	err := vs.validator.Struct(s)
	if err == nil {
		return &ValidationResult{
			IsValid: true,
			Errors:  make([]ValidationError, 0),
		}
	}

	// Handle validation errors
	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		// Convert validator errors to our ValidationError format
		var errors []ValidationError
		for _, err := range validationErrors {
			errors = append(errors, ValidationError{
				Field:   err.Field(),
				Message: getValidationMessage(err),
				Code:    err.Tag(),
			})
		}

		return &ValidationResult{
			IsValid: false,
			Errors:  errors,
		}
	}

	// Handle other types of errors (like InvalidValidationError)
	return &ValidationResult{
		IsValid: false,
		Errors: []ValidationError{
			{
				Field:   "field",
				Message: "validation failed",
				Code:    "VALIDATION_ERROR",
			},
		},
	}
}

// ValidateField validates a single field
func (vs *ValidatorService) ValidateField(field interface{}, tag string) *ValidationResult {
	err := vs.validator.Var(field, tag)
	if err == nil {
		return &ValidationResult{
			IsValid: true,
			Errors:  make([]ValidationError, 0),
		}
	}

	// Convert validator error to our ValidationError format
	if validationErrors, ok := err.(validator.ValidationErrors); ok && len(validationErrors) > 0 {
		validationErr := validationErrors[0]
		return &ValidationResult{
			IsValid: false,
			Errors: []ValidationError{
				{
					Field:   "field",
					Message: getValidationMessage(validationErr),
					Code:    validationErr.Tag(),
				},
			},
		}
	}

	// Fallback for other error types
	return &ValidationResult{
		IsValid: false,
		Errors: []ValidationError{
			{
				Field:   "field",
				Message: "validation failed",
				Code:    "VALIDATION_ERROR",
			},
		},
	}
}

// getValidationMessage converts validator error to human-readable message
func getValidationMessage(err validator.FieldError) string {
	field := err.Field()
	tag := err.Tag()
	param := err.Param()

	switch tag {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "min":
		return fmt.Sprintf("%s must be at least %s characters long", field, param)
	case "max":
		return fmt.Sprintf("%s must be no more than %s characters long", field, param)
	case "email":
		return fmt.Sprintf("%s must be a valid email address", field)
	case "alphanumspace":
		return fmt.Sprintf("%s must contain only letters, numbers, and spaces", field)
	case "companyname":
		return fmt.Sprintf("%s must be a valid company name", field)
	case "ssn":
		return fmt.Sprintf("%s must be a valid SSN (9 digits)", field)
	case "phone":
		return fmt.Sprintf("%s must be a valid phone number", field)
	case "len":
		return fmt.Sprintf("%s must be exactly %s characters long", field, param)
	case "numeric":
		return fmt.Sprintf("%s must contain only numbers", field)
	case "alpha":
		return fmt.Sprintf("%s must contain only letters", field)
	case "alphanum":
		return fmt.Sprintf("%s must contain only letters and numbers", field)
	default:
		return fmt.Sprintf("%s is invalid", field)
	}
}

// Custom validators for enterprise use

// validateAlphaNumSpace validates alphanumeric characters and spaces
func validateAlphaNumSpace(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	// Allow letters, numbers, and spaces
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == ' ') {
			return false
		}
	}
	return true
}

// validateCompanyName validates company name format
func validateCompanyName(fl validator.FieldLevel) bool {
	value := strings.TrimSpace(fl.Field().String())
	if len(value) < 2 || len(value) > 100 {
		return false
	}
	// Allow letters, numbers, spaces, hyphens, periods, and ampersands
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == ' ' || char == '-' || char == '.' || char == '&') {
			return false
		}
	}
	return true
}

// validateSSN validates Social Security Number format
func validateSSN(fl validator.FieldLevel) bool {
	value := strings.TrimSpace(fl.Field().String())
	// Remove any dashes or spaces
	value = strings.ReplaceAll(value, "-", "")
	value = strings.ReplaceAll(value, " ", "")

	// Must be exactly 9 digits
	if len(value) != 9 {
		return false
	}

	// All characters must be digits
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}

	return true
}

// validatePhone validates phone number format (E.164)
func validatePhone(fl validator.FieldLevel) bool {
	value := strings.TrimSpace(fl.Field().String())
	// Must start with + and contain only digits after that
	if len(value) < 10 || len(value) > 15 {
		return false
	}

	if value[0] != '+' {
		return false
	}

	// All characters after + must be digits
	for i := 1; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}

	return true
}
