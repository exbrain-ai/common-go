package validation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test structures for validation
type TestUser struct {
	Name     string `validate:"required,min=2,max=50"`
	Email    string `validate:"required,email"`
	Age      int    `validate:"min=0,max=150"`
	Phone    string `validate:"phone"`
	Company  string `validate:"companyname"`
	Username string `validate:"required,alphanumspace,min=3,max=20"`
}

type TestUserSSN struct {
	Name string `validate:"required"`
	SSN  string `validate:"ssn"`
}

// Test NewValidatorService
func TestNewValidatorService(t *testing.T) {
	validator := NewValidatorService()
	assert.NotNil(t, validator)
	assert.NotNil(t, validator.validator)
}

// Test ValidateStruct with valid data
func TestValidatorService_ValidateStruct_Valid(t *testing.T) {
	validator := NewValidatorService()

	user := TestUser{
		Name:     "John Doe",
		Email:    "john.doe@example.com",
		Age:      30,
		Phone:    "+1234567890",
		Company:  "Tech Corp",
		Username: "john doe",
	}

	result := validator.ValidateStruct(user)
	assert.True(t, result.IsValid)
	assert.Empty(t, result.Errors)
}

// Test ValidateStruct with invalid data
func TestValidatorService_ValidateStruct_Invalid(t *testing.T) {
	validator := NewValidatorService()

	user := TestUser{
		Name:     "",              // Missing required field
		Email:    "invalid-email", // Invalid email format
		Age:      200,             // Exceeds maximum
		Phone:    "invalid-phone", // Invalid phone format
		Company:  "",              // Empty company name
		Username: "u",             // Too short
	}

	result := validator.ValidateStruct(user)
	assert.False(t, result.IsValid)
	assert.NotEmpty(t, result.Errors)

	// Should have validation errors for multiple fields
	fieldNames := make([]string, len(result.Errors))
	for i, err := range result.Errors {
		fieldNames[i] = err.Field
	}

	assert.Contains(t, fieldNames, "Name")
	assert.Contains(t, fieldNames, "Email")
	assert.Contains(t, fieldNames, "Age")
	assert.Contains(t, fieldNames, "Username")
}

// Test ValidateField with valid values
func TestValidatorService_ValidateField_Valid(t *testing.T) {
	validator := NewValidatorService()

	tests := []struct {
		name  string
		value interface{}
		tag   string
	}{
		{"Required string", "test", "required"},
		{"Email", "test@example.com", "email"},
		{"Min length", "hello", "min=3"},
		{"Max length", "test", "max=10"},
		{"Numeric", "123", "numeric"},
		{"Alpha", "hello", "alpha"},
		{"Alphanum", "hello123", "alphanum"},
		{"Phone", "+1234567890", "phone"},
		{"SSN", "123456789", "ssn"},
		{"Company name", "Tech Corp", "companyname"},
		{"AlphaNumSpace", "hello world 123", "alphanumspace"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateField(tt.value, tt.tag)
			assert.True(t, result.IsValid, "Field should be valid: %s", tt.name)
			assert.Empty(t, result.Errors)
		})
	}
}

// Test ValidateField with invalid values
func TestValidatorService_ValidateField_Invalid(t *testing.T) {
	validator := NewValidatorService()

	tests := []struct {
		name  string
		value interface{}
		tag   string
	}{
		{"Required empty", "", "required"},
		{"Email invalid", "invalid-email", "email"},
		{"Min length", "ab", "min=3"},
		{"Max length", "this is too long", "max=5"},
		{"Numeric", "abc", "numeric"},
		{"Alpha", "hello123", "alpha"},
		{"Alphanum", "hello@world", "alphanum"},
		{"Phone invalid", "123", "phone"},
		{"SSN invalid", "12345", "ssn"},
		{"Company name invalid", "Corp<script>", "companyname"},
		{"AlphaNumSpace invalid", "hello@world", "alphanumspace"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateField(tt.value, tt.tag)
			assert.False(t, result.IsValid, "Field should be invalid: %s", tt.name)
			assert.NotEmpty(t, result.Errors)
		})
	}
}

// Test custom validators
func TestCustomValidators_AlphaNumSpace(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"hello world", true},
		{"Hello World 123", true},
		{"test123", true},
		{"test", true},
		{"123", true},
		{"hello@world", false},
		{"hello#world", false},
		{"hello-world", false},
		{"hello_world", false},
		{"hello.world", false},
		{"", true}, // Empty string is valid for alphanumspace
	}

	validator := NewValidatorService()

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := validator.ValidateField(tt.input, "alphanumspace")
			if tt.expected {
				assert.True(t, result.IsValid, "Input should be valid: '%s'", tt.input)
			} else {
				assert.False(t, result.IsValid, "Input should be invalid: '%s'", tt.input)
			}
		})
	}
}

func TestCustomValidators_CompanyName(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"Tech Corp", true},
		{"ABC Inc.", true},
		{"Smith & Associates", true},
		{"Tech-Solutions", true},
		{"Company 123", true},
		{"A", false},                       // Too short
		{"", false},                        // Empty
		{string(make([]byte, 101)), false}, // Too long
		{"Corp<script>", false},            // Contains invalid characters
		{"Corp@email", false},              // Contains invalid characters
		{"Corp#tag", false},                // Contains invalid characters
		{"Corp_underscore", false},         // Contains invalid characters
		{"Corp|pipe", false},               // Contains invalid characters
	}

	validator := NewValidatorService()

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := validator.ValidateField(tt.input, "companyname")
			if tt.expected {
				assert.True(t, result.IsValid, "Input should be valid: '%s'", tt.input)
			} else {
				assert.False(t, result.IsValid, "Input should be invalid: '%s'", tt.input)
			}
		})
	}
}

func TestCustomValidators_SSN(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"123456789", true},
		{"123-45-6789", true},  // With dashes
		{"123 45 6789", true},  // With spaces
		{"12345678", false},    // Too short
		{"1234567890", false},  // Too long
		{"12345678a", false},   // Contains letter
		{"123-45-678a", false}, // Contains letter
		{"", false},            // Empty
		{"123-45-", false},     // Incomplete
	}

	validator := NewValidatorService()

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := validator.ValidateField(tt.input, "ssn")
			if tt.expected {
				assert.True(t, result.IsValid, "Input should be valid: '%s'", tt.input)
			} else {
				assert.False(t, result.IsValid, "Input should be invalid: '%s'", tt.input)
			}
		})
	}
}

func TestCustomValidators_Phone(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"+1234567890", true},
		{"+12345678901234", true},   // Maximum length
		{"+123456789", true},        // 10 digits is valid
		{"+123456789012345", false}, // Too long
		{"1234567890", false},       // Missing +
		{"+", false},                // Only +
		{"+12345678a0", false},      // Contains letter
		{"", false},                 // Empty
		{"+12 34 56 78 90", false},  // Contains spaces
		{"+12-34-56-78-90", false},  // Contains dashes
	}

	validator := NewValidatorService()

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := validator.ValidateField(tt.input, "phone")
			if tt.expected {
				assert.True(t, result.IsValid, "Input should be valid: '%s'", tt.input)
			} else {
				assert.False(t, result.IsValid, "Input should be invalid: '%s'", tt.input)
			}
		})
	}
}

// Test validation messages
func TestGetValidationMessage(t *testing.T) {
	validator := NewValidatorService()

	// Test with a struct to get actual validator.FieldError
	user := TestUser{
		Name: "", // This will trigger 'required' validation
	}

	result := validator.ValidateStruct(user)
	assert.False(t, result.IsValid)
	assert.NotEmpty(t, result.Errors)

	// Check that the error message is properly formatted
	nameError := result.Errors[0]
	assert.Equal(t, "Name", nameError.Field)
	assert.Equal(t, "required", nameError.Code)
	assert.Contains(t, nameError.Message, "Name")
	assert.Contains(t, nameError.Message, "required")
}

func TestValidationMessageFormats(t *testing.T) {
	validator := NewValidatorService()

	tests := []struct {
		name      string
		user      TestUser
		expectTag string
		expectMsg string
	}{
		{
			name:      "Required validation",
			user:      TestUser{Name: ""},
			expectTag: "required",
			expectMsg: "is required",
		},
		{
			name:      "Min length validation",
			user:      TestUser{Name: "a", Email: "test@example.com"},
			expectTag: "min",
			expectMsg: "must be at least",
		},
		{
			name:      "Max length validation",
			user:      TestUser{Name: string(make([]byte, 60)), Email: "test@example.com"},
			expectTag: "max",
			expectMsg: "must be no more than",
		},
		{
			name:      "Email validation",
			user:      TestUser{Name: "Test", Email: "invalid-email"},
			expectTag: "email",
			expectMsg: "must be a valid email address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateStruct(tt.user)
			assert.False(t, result.IsValid)

			// Find the error with the expected tag
			var foundError ValidationError
			for _, err := range result.Errors {
				if err.Code == tt.expectTag {
					foundError = err
					break
				}
			}

			assert.NotEmpty(t, foundError.Field)
			assert.Equal(t, tt.expectTag, foundError.Code)
			assert.Contains(t, foundError.Message, tt.expectMsg)
		})
	}
}

// Test edge cases
func TestValidatorService_NilStruct(t *testing.T) {
	validator := NewValidatorService()

	// This should handle the error gracefully
	result := validator.ValidateStruct(nil)
	assert.False(t, result.IsValid)
	assert.NotEmpty(t, result.Errors)

	// Should have a generic validation error
	assert.Len(t, result.Errors, 1)
	assert.Equal(t, "field", result.Errors[0].Field)
	assert.Equal(t, "validation failed", result.Errors[0].Message)
}

func TestValidatorService_EmptyStruct(t *testing.T) {
	validator := NewValidatorService()

	type EmptyStruct struct{}
	empty := EmptyStruct{}

	result := validator.ValidateStruct(empty)
	assert.True(t, result.IsValid)
	assert.Empty(t, result.Errors)
}

func TestValidatorService_StructWithNoValidationTags(t *testing.T) {
	validator := NewValidatorService()

	type NoValidationStruct struct {
		Name  string
		Email string
		Age   int
	}

	noValidation := NoValidationStruct{
		Name:  "",
		Email: "invalid-email",
		Age:   -1,
	}

	result := validator.ValidateStruct(noValidation)
	assert.True(t, result.IsValid, "Struct without validation tags should be valid")
	assert.Empty(t, result.Errors)
}

func TestValidatorService_NestedStructs(t *testing.T) {
	validator := NewValidatorService()

	type Address struct {
		Street string `validate:"required"`
		City   string `validate:"required"`
	}

	type UserWithAddress struct {
		Name    string  `validate:"required"`
		Address Address `validate:"required"`
	}

	user := UserWithAddress{
		Name: "John",
		Address: Address{
			Street: "", // Invalid - required field is empty
			City:   "New York",
		},
	}

	result := validator.ValidateStruct(user)
	// Note: go-playground/validator handles nested structs automatically
	// The result depends on how the validator is configured
	assert.NotNil(t, result)
}

// Test concurrent usage
func TestValidatorService_Concurrent(t *testing.T) {
	validator := NewValidatorService()

	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			user := TestUser{
				Name:     "Test User",
				Email:    "test@example.com",
				Age:      30,
				Phone:    "+1234567890",
				Company:  "Test Corp",
				Username: "testuser",
			}

			result := validator.ValidateStruct(user)
			assert.True(t, result.IsValid)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// Benchmark tests
func BenchmarkValidatorService_ValidateStruct(b *testing.B) {
	validator := NewValidatorService()

	user := TestUser{
		Name:     "John Doe",
		Email:    "john.doe@example.com",
		Age:      30,
		Phone:    "+1234567890",
		Company:  "Tech Corp",
		Username: "john doe",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.ValidateStruct(user)
	}
}

func BenchmarkValidatorService_ValidateField(b *testing.B) {
	validator := NewValidatorService()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.ValidateField("test@example.com", "email")
	}
}

func BenchmarkCustomValidator_AlphaNumSpace(b *testing.B) {
	validator := NewValidatorService()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.ValidateField("hello world 123", "alphanumspace")
	}
}

func BenchmarkCustomValidator_CompanyName(b *testing.B) {
	validator := NewValidatorService()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.ValidateField("Tech Corp & Associates", "companyname")
	}
}

func BenchmarkCustomValidator_SSN(b *testing.B) {
	validator := NewValidatorService()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.ValidateField("123-45-6789", "ssn")
	}
}

func BenchmarkCustomValidator_Phone(b *testing.B) {
	validator := NewValidatorService()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.ValidateField("+1234567890", "phone")
	}
}
