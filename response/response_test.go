package response

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	appErrors "github.com/medbai2/common-go/errors"
	"github.com/medbai2/common-go/testutils"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// Test Success function
func TestSuccess(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.GET("/test", func(c *gin.Context) {
		Success(c, map[string]string{"message": "test data"})
	})

	req := hts.SetupRequest(http.MethodGet, "/test")
	hts.ExecuteRequest(req)

	hts.AssertResponseStatus(http.StatusOK)

	var response APIResponse
	err := json.Unmarshal(hts.Recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	hts.AssertTrue(response.Success)
	hts.AssertNotEmpty(response.Timestamp)
	hts.AssertNotNil(response.Data)
	hts.AssertNil(response.Error)

	// Check data content
	data, ok := response.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "test data", data["message"])
}

func TestSuccessWithMessage(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.GET("/test", func(c *gin.Context) {
		SuccessWithMessage(c, "Custom success message", map[string]string{"id": "123"})
	})

	req := hts.SetupRequest(http.MethodGet, "/test")
	hts.ExecuteRequest(req)

	hts.AssertResponseStatus(http.StatusOK)

	var response APIResponse
	err := json.Unmarshal(hts.Recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	hts.AssertTrue(response.Success)
	hts.AssertEqual("Custom success message", response.Message)
	hts.AssertNotNil(response.Data)
}

func TestCreated(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.POST("/test", func(c *gin.Context) {
		Created(c, map[string]interface{}{"id": 123, "name": "New Item"})
	})

	req := hts.SetupRequest(http.MethodPost, "/test")
	hts.ExecuteRequest(req)

	hts.AssertResponseStatus(http.StatusCreated)

	var response APIResponse
	err := json.Unmarshal(hts.Recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	hts.AssertTrue(response.Success)
	hts.AssertNotNil(response.Data)
}

func TestNoContent(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.DELETE("/test", func(c *gin.Context) {
		NoContent(c)
	})

	req := hts.SetupRequest(http.MethodDelete, "/test")
	hts.ExecuteRequest(req)

	hts.AssertResponseStatus(http.StatusNoContent)
	hts.AssertEmpty(hts.Recorder.Body.String())
}

func TestError(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.GET("/test-error", func(c *gin.Context) {
		appErr := appErrors.NewInvalidInput("test field")
		Error(c, appErr)
	})

	req := hts.SetupRequest(http.MethodGet, "/test-error")
	hts.ExecuteRequest(req)

	hts.AssertResponseStatus(http.StatusBadRequest)

	var response APIResponse
	err := json.Unmarshal(hts.Recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	hts.AssertFalse(response.Success)
	hts.AssertNotNil(response.Error)
	hts.AssertEqual("INVALID_INPUT", response.Error.Code)
}

func TestErrorWithMessage(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.GET("/test-error-msg", func(c *gin.Context) {
		ErrorWithMessage(c, errors.New("underlying error"), "Custom error message")
	})

	req := hts.SetupRequest(http.MethodGet, "/test-error-msg")
	hts.ExecuteRequest(req)

	hts.AssertResponseStatus(http.StatusInternalServerError)

	var response APIResponse
	err := json.Unmarshal(hts.Recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	hts.AssertFalse(response.Success)
	hts.AssertNotNil(response.Error)
	hts.AssertEqual("Custom error message", response.Error.Message)
}

func TestPaginated(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.GET("/test-paginated", func(c *gin.Context) {
		data := []map[string]interface{}{
			{"id": 1, "name": "Item 1"},
			{"id": 2, "name": "Item 2"},
		}
		Paginated(c, data, 1, 10, 25)
	})

	req := hts.SetupRequest(http.MethodGet, "/test-paginated")
	hts.ExecuteRequest(req)

	hts.AssertResponseStatus(http.StatusOK)

	var response APIResponse
	err := json.Unmarshal(hts.Recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	hts.AssertTrue(response.Success)
	hts.AssertNotNil(response.Data)

	// Check pagination structure
	data, ok := response.Data.(map[string]interface{})
	require.True(t, ok)

	pagination, ok := data["pagination"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(1), pagination["page"])
	assert.Equal(t, float64(10), pagination["pageSize"])
	assert.Equal(t, float64(25), pagination["total"])
	assert.Equal(t, float64(3), pagination["totalPages"])
}

func TestBadRequest(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.GET("/test-bad-request", func(c *gin.Context) {
		BadRequest(c, "Invalid request data")
	})

	req := hts.SetupRequest(http.MethodGet, "/test-bad-request")
	hts.ExecuteRequest(req)

	hts.AssertResponseStatus(http.StatusBadRequest)

	var response APIResponse
	err := json.Unmarshal(hts.Recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	hts.AssertFalse(response.Success)
	hts.AssertNotNil(response.Error)
	hts.AssertEqual("Invalid request data", response.Error.Message)
}

func TestUnauthorized(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.GET("/test-unauthorized", func(c *gin.Context) {
		Unauthorized(c, "Access denied")
	})

	req := hts.SetupRequest(http.MethodGet, "/test-unauthorized")
	hts.ExecuteRequest(req)

	hts.AssertResponseStatus(http.StatusUnauthorized)

	var response APIResponse
	err := json.Unmarshal(hts.Recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	hts.AssertFalse(response.Success)
	hts.AssertNotNil(response.Error)
	hts.AssertEqual("Access denied", response.Error.Message)
}

func TestForbidden(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.GET("/test-forbidden", func(c *gin.Context) {
		Forbidden(c, "Insufficient permissions")
	})

	req := hts.SetupRequest(http.MethodGet, "/test-forbidden")
	hts.ExecuteRequest(req)

	hts.AssertResponseStatus(http.StatusForbidden)

	var response APIResponse
	err := json.Unmarshal(hts.Recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	hts.AssertFalse(response.Success)
	hts.AssertNotNil(response.Error)
	hts.AssertEqual("Insufficient permissions", response.Error.Message)
}

func TestNotFound(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.GET("/test-not-found", func(c *gin.Context) {
		NotFound(c, "Resource not found")
	})

	req := hts.SetupRequest(http.MethodGet, "/test-not-found")
	hts.ExecuteRequest(req)

	hts.AssertResponseStatus(http.StatusNotFound)

	var response APIResponse
	err := json.Unmarshal(hts.Recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	hts.AssertFalse(response.Success)
	hts.AssertNotNil(response.Error)
	hts.AssertEqual("resource not found: Resource not found", response.Error.Message)
}

func TestConflict(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.GET("/test-conflict", func(c *gin.Context) {
		Conflict(c, "Resource already exists")
	})

	req := hts.SetupRequest(http.MethodGet, "/test-conflict")
	hts.ExecuteRequest(req)

	hts.AssertResponseStatus(http.StatusConflict)

	var response APIResponse
	err := json.Unmarshal(hts.Recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	hts.AssertFalse(response.Success)
	hts.AssertNotNil(response.Error)
	hts.AssertEqual("Resource already exists", response.Error.Message)
}

func TestInternalServerError(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.GET("/test-internal-error", func(c *gin.Context) {
		InternalServerError(c, "Something went wrong")
	})

	req := hts.SetupRequest(http.MethodGet, "/test-internal-error")
	hts.ExecuteRequest(req)

	hts.AssertResponseStatus(http.StatusInternalServerError)

	var response APIResponse
	err := json.Unmarshal(hts.Recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	hts.AssertFalse(response.Success)
	hts.AssertNotNil(response.Error)
	hts.AssertEqual("Something went wrong", response.Error.Message)
}

func TestTooManyRequests(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.GET("/test-too-many-requests", func(c *gin.Context) {
		ErrorWithMessage(c, appErrors.NewRateLimitExceeded(""), "Rate limit exceeded")
	})

	req := hts.SetupRequest(http.MethodGet, "/test-too-many-requests")
	hts.ExecuteRequest(req)

	hts.AssertResponseStatus(http.StatusTooManyRequests)

	var response APIResponse
	err := json.Unmarshal(hts.Recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	hts.AssertFalse(response.Success)
	hts.AssertNotNil(response.Error)
	hts.AssertEqual("Rate limit exceeded", response.Error.Message)
}

func TestServiceUnavailable(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.GET("/test-service-unavailable", func(c *gin.Context) {
		ServiceUnavailable(c, "Service temporarily unavailable")
	})

	req := hts.SetupRequest(http.MethodGet, "/test-service-unavailable")
	hts.ExecuteRequest(req)

	hts.AssertResponseStatus(http.StatusServiceUnavailable)

	var response APIResponse
	err := json.Unmarshal(hts.Recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	hts.AssertFalse(response.Success)
	hts.AssertNotNil(response.Error)
	hts.AssertEqual("Service temporarily unavailable", response.Error.Message)
}

func TestConcurrentAccess(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.GET("/test", func(c *gin.Context) {
		Success(c, map[string]string{"message": "concurrent test"})
	})

	// Run multiple concurrent requests
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			req := hts.SetupRequest(http.MethodGet, "/test")
			hts.ExecuteRequest(req)
			hts.AssertResponseStatus(http.StatusOK)
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestRequestIDExtraction(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.GET("/test", func(c *gin.Context) {
		// Set request ID in context
		c.Set("requestId", "test-request-123")
		Success(c, map[string]string{"message": "test"})
	})

	req := hts.SetupRequest(http.MethodGet, "/test")
	hts.ExecuteRequest(req)

	hts.AssertResponseStatus(http.StatusOK)

	var response APIResponse
	err := json.Unmarshal(hts.Recorder.Body.Bytes(), &response)
	require.NoError(t, err)

	hts.AssertEqual("test-request-123", response.RequestID)
}
