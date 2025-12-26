package response

import (
	"net/http"
	"time"

	"github.com/medbai2/common-go/errors"

	"github.com/gin-gonic/gin"
)

// APIResponse represents a standard API response structure
type APIResponse struct {
	Success   bool        `json:"success"`
	Message   string      `json:"message,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Error     *APIError   `json:"error,omitempty"`
	Timestamp string      `json:"timestamp"`
	RequestID string      `json:"requestId,omitempty"`
}

// APIError represents error information in API responses
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// Success sends a successful response with data
func Success(c *gin.Context, data interface{}) {
	response := APIResponse{
		Success:   true,
		Data:      data,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: getRequestID(c),
	}

	c.JSON(http.StatusOK, response)
}

// SuccessWithMessage sends a successful response with data and custom message
func SuccessWithMessage(c *gin.Context, message string, data interface{}) {
	response := APIResponse{
		Success:   true,
		Message:   message,
		Data:      data,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: getRequestID(c),
	}

	c.JSON(http.StatusOK, response)
}

// Created sends a 201 Created response
func Created(c *gin.Context, data interface{}) {
	response := APIResponse{
		Success:   true,
		Data:      data,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: getRequestID(c),
	}

	c.JSON(http.StatusCreated, response)
}

// Error sends an error response based on AppError
func Error(c *gin.Context, err error) {
	appErr := errors.GetAppError(err)
	if appErr == nil {
		// If it's not an AppError, create a generic internal error
		appErr = errors.NewInternalError(err)
	}

	apiError := &APIError{
		Code:    string(appErr.Code),
		Message: appErr.Message,
		Details: appErr.Details,
	}

	response := APIResponse{
		Success:   false,
		Error:     apiError,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: getRequestID(c),
	}

	c.JSON(appErr.HTTPStatus, response)
}

// ErrorWithMessage sends an error response with custom message
func ErrorWithMessage(c *gin.Context, err error, message string) {
	appErr := errors.GetAppError(err)
	if appErr == nil {
		// If it's not an AppError, create a generic internal error
		appErr = errors.NewInternalError(err)
	}

	apiError := &APIError{
		Code:    string(appErr.Code),
		Message: message,
		Details: appErr.Details,
	}

	response := APIResponse{
		Success:   false,
		Error:     apiError,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: getRequestID(c),
	}

	c.JSON(appErr.HTTPStatus, response)
}

// BadRequest sends a 400 Bad Request response
func BadRequest(c *gin.Context, message string) {
	apiError := &APIError{
		Code:    string(errors.ErrCodeInvalidInput),
		Message: message,
	}

	response := APIResponse{
		Success:   false,
		Error:     apiError,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: getRequestID(c),
	}

	c.JSON(http.StatusBadRequest, response)
}

// Unauthorized sends a 401 Unauthorized response
func Unauthorized(c *gin.Context, message string) {
	if message == "" {
		message = errors.MsgUnauthorized
	}

	apiError := &APIError{
		Code:    string(errors.ErrCodeUnauthorized),
		Message: message,
	}

	response := APIResponse{
		Success:   false,
		Error:     apiError,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: getRequestID(c),
	}

	c.JSON(http.StatusUnauthorized, response)
}

// Forbidden sends a 403 Forbidden response
func Forbidden(c *gin.Context, message string) {
	if message == "" {
		message = errors.MsgForbidden
	}

	apiError := &APIError{
		Code:    string(errors.ErrCodeForbidden),
		Message: message,
	}

	response := APIResponse{
		Success:   false,
		Error:     apiError,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: getRequestID(c),
	}

	c.JSON(http.StatusForbidden, response)
}

// NotFound sends a 404 Not Found response
func NotFound(c *gin.Context, resource string) {
	message := errors.GetMessage(errors.ErrCodeNotFound, resource)

	apiError := &APIError{
		Code:    string(errors.ErrCodeNotFound),
		Message: message,
	}

	response := APIResponse{
		Success:   false,
		Error:     apiError,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: getRequestID(c),
	}

	c.JSON(http.StatusNotFound, response)
}

// Conflict sends a 409 Conflict response
func Conflict(c *gin.Context, message string) {
	apiError := &APIError{
		Code:    string(errors.ErrCodeBusinessRule),
		Message: message,
	}

	response := APIResponse{
		Success:   false,
		Error:     apiError,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: getRequestID(c),
	}

	c.JSON(http.StatusConflict, response)
}

// InternalServerError sends a 500 Internal Server Error response
func InternalServerError(c *gin.Context, message string) {
	if message == "" {
		message = errors.MsgInternal
	}

	apiError := &APIError{
		Code:    string(errors.ErrCodeInternal),
		Message: message,
	}

	response := APIResponse{
		Success:   false,
		Error:     apiError,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: getRequestID(c),
	}

	c.JSON(http.StatusInternalServerError, response)
}

// ServiceUnavailable sends a 503 Service Unavailable response
func ServiceUnavailable(c *gin.Context, message string) {
	if message == "" {
		message = errors.MsgServiceUnavailable
	}

	apiError := &APIError{
		Code:    string(errors.ErrCodeServiceUnavailable),
		Message: message,
	}

	response := APIResponse{
		Success:   false,
		Error:     apiError,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: getRequestID(c),
	}

	c.JSON(http.StatusServiceUnavailable, response)
}

// NoContent sends a 204 No Content response
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// Paginated sends a paginated response with metadata
func Paginated(c *gin.Context, data interface{}, page, pageSize, total int) {
	totalPages := (total + pageSize - 1) / pageSize

	pagination := map[string]interface{}{
		"page":       page,
		"pageSize":   pageSize,
		"total":      total,
		"totalPages": totalPages,
		"hasNext":    page < totalPages,
		"hasPrev":    page > 1,
	}

	responseData := map[string]interface{}{
		"items":      data,
		"pagination": pagination,
	}

	response := APIResponse{
		Success:   true,
		Data:      responseData,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: getRequestID(c),
	}

	c.JSON(http.StatusOK, response)
}

// ValidationError sends a validation error response
func ValidationError(c *gin.Context, validationErr error) {
	appErr := errors.GetAppError(validationErr)
	if appErr == nil {
		// If it's not an AppError, create a generic validation error
		appErr = errors.NewInvalidInput("validation failed")
	}

	apiError := &APIError{
		Code:    string(appErr.Code),
		Message: appErr.Message,
		Details: appErr.Details,
	}

	response := APIResponse{
		Success:   false,
		Error:     apiError,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: getRequestID(c),
	}

	c.JSON(http.StatusBadRequest, response)
}

// getRequestID extracts request ID from gin context
func getRequestID(c *gin.Context) string {
	if requestID, exists := c.Get("requestId"); exists {
		if id, ok := requestID.(string); ok {
			return id
		}
	}
	return ""
}

// Health sends a health check response
func Health(c *gin.Context, status string, checks map[string]interface{}) {
	data := map[string]interface{}{
		"status":    status,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"checks":    checks,
	}

	var httpStatus int
	var success bool

	// Backward compatibility: "ok" and "healthy" both return 200
	// Only "degraded", "unhealthy", "down", etc. return 503
	switch status {
	case "healthy", "ok":
		httpStatus = http.StatusOK
		success = true
	default:
		httpStatus = http.StatusServiceUnavailable
		success = false
	}

	response := APIResponse{
		Success:   success,
		Data:      data,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: getRequestID(c),
	}

	c.JSON(httpStatus, response)
}
