package middleware

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/medbai2/common-go/testutils"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// MiddlewareTestCase represents a middleware test case
type MiddlewareTestCase struct {
	Name             string
	Method           string
	Path             string
	Headers          map[string]string
	ExpectedStatus   int
	ExpectedHeaders  map[string]string
	ExpectedBody     string
	Setup            func()
	Cleanup          func()
	ValidateResponse func(t *testing.T, hts *testutils.HTTPTestSuite)
}

// runMiddlewareTestCase runs a single middleware test case
func runMiddlewareTestCase(t *testing.T, tc MiddlewareTestCase) {
	if tc.Setup != nil {
		tc.Setup()
	}
	if tc.Cleanup != nil {
		defer tc.Cleanup()
	}

	hts := testutils.NewHTTPTestSuite(t)

	// Add middleware and route
	hts.Router.Use(Logger())
	hts.Router.Use(CORS(86400))
	hts.Router.Handle(tc.Method, tc.Path, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create request with headers
	req := hts.SetupRequest(tc.Method, tc.Path)
	for key, value := range tc.Headers {
		req.Header.Set(key, value)
	}

	// Execute request
	hts.ExecuteRequest(req)

	// Basic assertions
	hts.AssertResponseStatus(tc.ExpectedStatus)

	// Check expected headers
	for key, expectedValue := range tc.ExpectedHeaders {
		hts.AssertResponseHeader(key, expectedValue)
	}

	// Check expected body
	if tc.ExpectedBody != "" {
		hts.AssertResponseContains(tc.ExpectedBody)
	}

	// Custom validation
	if tc.ValidateResponse != nil {
		tc.ValidateResponse(t, hts)
	}
}

// Test Logger middleware
func TestLogger(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	// Add logger middleware and test route
	hts.Router.Use(Logger())
	hts.Router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Test GET request
	req := hts.SetupRequest(http.MethodGet, "/test")
	hts.ExecuteRequest(req)

	hts.AssertResponseStatus(http.StatusOK)
	hts.AssertResponseContains("success")
}

// Test CORS middleware
func TestCORS(t *testing.T) {
	testCases := []MiddlewareTestCase{
		{
			Name:   "Basic CORS Request",
			Method: http.MethodGet,
			Path:   "/test",
			Headers: map[string]string{
				"Origin": "https://example.com",
			},
			ExpectedStatus: http.StatusOK,
			ExpectedHeaders: map[string]string{
				"Access-Control-Allow-Origin":  "https://example.com",
				"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
				"Access-Control-Allow-Headers": "Origin, Content-Type, Accept, Authorization",
			},
		},
		{
			Name:   "Preflight OPTIONS Request",
			Method: http.MethodOptions,
			Path:   "/test",
			Headers: map[string]string{
				"Origin":                         "https://example.com",
				"Access-Control-Request-Method":  "POST",
				"Access-Control-Request-Headers": "Content-Type, Authorization",
			},
			ExpectedStatus: http.StatusNoContent,
			ExpectedHeaders: map[string]string{
				"Access-Control-Allow-Origin":  "https://example.com",
				"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
				"Access-Control-Allow-Headers": "Origin, Content-Type, Accept, Authorization",
				"Access-Control-Max-Age":       "86400",
			},
		},
		{
			Name:   "CORS with Custom Headers",
			Method: http.MethodPost,
			Path:   "/test",
			Headers: map[string]string{
				"Origin":        "https://app.example.com",
				"Content-Type":  "application/json",
				"Authorization": "Bearer token123",
			},
			ExpectedStatus: http.StatusOK,
			ExpectedHeaders: map[string]string{
				"Access-Control-Allow-Origin": "https://app.example.com",
			},
		},
		{
			Name:   "CORS with Different Origin",
			Method: http.MethodGet,
			Path:   "/test",
			Headers: map[string]string{
				"Origin": "https://different.com",
			},
			ExpectedStatus: http.StatusOK,
			ExpectedHeaders: map[string]string{
				"Access-Control-Allow-Origin": "https://different.com",
			},
		},
		{
			Name:           "CORS without Origin Header",
			Method:         http.MethodGet,
			Path:           "/test",
			Headers:        map[string]string{},
			ExpectedStatus: http.StatusOK,
			ExpectedHeaders: map[string]string{
				"Access-Control-Allow-Origin": "*",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			runMiddlewareTestCase(t, tc)
		})
	}
}

// Test CORS with different configurations
func TestCORS_Configurations(t *testing.T) {
	testCases := []struct {
		Name            string
		SetupCORS       func() gin.HandlerFunc
		Method          string
		Path            string
		Headers         map[string]string
		ExpectedHeaders map[string]string
	}{
		{
			Name: "CORS with Custom Max Age",
			SetupCORS: func() gin.HandlerFunc {
				return CORS(3600)
			},
			Method: http.MethodOptions,
			Path:   "/test",
			Headers: map[string]string{
				"Origin": "https://example.com",
			},
			ExpectedHeaders: map[string]string{
				"Access-Control-Max-Age": "3600",
			},
		},
		{
			Name: "CORS with Custom Methods",
			SetupCORS: func() gin.HandlerFunc {
				return CORS(86400)
			},
			Method: http.MethodOptions,
			Path:   "/test",
			Headers: map[string]string{
				"Origin": "https://example.com",
			},
			ExpectedHeaders: map[string]string{
				"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
			},
		},
		{
			Name: "CORS with Custom Headers",
			SetupCORS: func() gin.HandlerFunc {
				return CORS(86400)
			},
			Method: http.MethodOptions,
			Path:   "/test",
			Headers: map[string]string{
				"Origin": "https://example.com",
			},
			ExpectedHeaders: map[string]string{
				"Access-Control-Allow-Headers": "Origin, Content-Type, Accept, Authorization",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			hts := testutils.NewHTTPTestSuite(t)

			// Add custom CORS middleware
			hts.Router.Use(tc.SetupCORS())
			hts.Router.Handle(tc.Method, tc.Path, func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Create request
			req := hts.SetupRequest(tc.Method, tc.Path)
			for key, value := range tc.Headers {
				req.Header.Set(key, value)
			}

			// Execute request
			hts.ExecuteRequest(req)

			// Check expected headers
			for key, expectedValue := range tc.ExpectedHeaders {
				hts.AssertResponseHeader(key, expectedValue)
			}
		})
	}
}

// Test middleware chaining
func TestMiddlewareChaining(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	// Add multiple middleware
	hts.Router.Use(Logger())
	hts.Router.Use(CORS(86400))
	hts.Router.Use(func(c *gin.Context) {
		c.Header("X-Custom-Middleware", "test")
		c.Next()
	})

	hts.Router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Test request
	req := hts.SetupRequest(http.MethodGet, "/test")
	req.Header.Set("Origin", "https://example.com")
	hts.ExecuteRequest(req)

	// Verify all middleware executed
	hts.AssertResponseStatus(http.StatusOK)
	hts.AssertResponseHeader("X-Custom-Middleware", "test")
	hts.AssertResponseHeader("Access-Control-Allow-Origin", "https://example.com")
	hts.AssertResponseContains("success")
}

// Test middleware error handling
func TestMiddlewareErrorHandling(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	// Add middleware that might cause errors
	hts.Router.Use(Logger())
	hts.Router.Use(CORS(86400))
	hts.Router.Use(func(c *gin.Context) {
		// Simulate an error condition
		if c.GetHeader("X-Force-Error") == "true" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "forced error"})
			c.Abort()
			return
		}
		c.Next()
	})

	hts.Router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Test normal request
	req := hts.SetupRequest(http.MethodGet, "/test")
	hts.ExecuteRequest(req)
	hts.AssertResponseStatus(http.StatusOK)

	// Test error request - create new test suite for clean state
	hts2 := testutils.NewHTTPTestSuite(t)
	hts2.Router.Use(Logger())
	hts2.Router.Use(CORS(86400))
	hts2.Router.Use(func(c *gin.Context) {
		// Simulate an error condition
		if c.GetHeader("X-Force-Error") == "true" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "forced error"})
			c.Abort()
			return
		}
		c.Next()
	})
	hts2.Router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req2 := hts2.SetupRequest(http.MethodGet, "/test")
	req2.Header.Set("X-Force-Error", "true")
	hts2.ExecuteRequest(req2)
	hts2.AssertResponseStatus(http.StatusInternalServerError)
	hts2.AssertResponseContains("forced error")
}

// Test concurrent middleware execution
func TestConcurrentMiddlewareExecution(t *testing.T) {
	// Run multiple concurrent requests
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			// Create a new test suite for each goroutine to avoid concurrent access
			hts := testutils.NewHTTPTestSuite(t)

			// Add middleware
			hts.Router.Use(Logger())
			hts.Router.Use(CORS(86400))
			hts.Router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			req := hts.SetupRequest(http.MethodGet, "/test")
			req.Header.Set("Origin", "https://example.com")
			hts.ExecuteRequest(req)
			hts.AssertResponseStatus(http.StatusOK)
			done <- true
		}()
	}

	// Wait for all requests to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// Test middleware performance
func TestMiddlewarePerformance(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	// Add middleware
	hts.Router.Use(Logger())
	hts.Router.Use(CORS(86400))
	hts.Router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Measure performance
	start := time.Now()
	for i := 0; i < 100; i++ {
		req := hts.SetupRequest(http.MethodGet, "/test")
		hts.ExecuteRequest(req)
	}
	duration := time.Since(start)

	// Verify performance (should be fast)
	assert.Less(t, duration, 1*time.Second, "Middleware should be fast")
}

// Test edge cases
func TestMiddlewareEdgeCases(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	// Test with empty path
	hts.Router.Use(Logger())
	hts.Router.Use(CORS(86400))
	hts.Router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "root"})
	})

	req := hts.SetupRequest(http.MethodGet, "/")
	hts.ExecuteRequest(req)
	hts.AssertResponseStatus(http.StatusOK)

	// Test with long path
	longPath := "/" + strings.Repeat("a", 1000)
	hts.Router.GET(longPath, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "long path"})
	})

	req = hts.SetupRequest(http.MethodGet, longPath)
	hts.ExecuteRequest(req)
	hts.AssertResponseStatus(http.StatusOK)

	// Test with special characters in headers
	req = hts.SetupRequest(http.MethodGet, "/")
	req.Header.Set("Origin", "https://example.com/path with spaces")
	hts.ExecuteRequest(req)
	hts.AssertResponseStatus(http.StatusOK)
}

// Test CORS with different HTTP methods
func TestCORS_DifferentMethods(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.Use(CORS(86400))
	hts.Router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"method": "GET"})
	})
	hts.Router.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"method": "POST"})
	})
	hts.Router.PUT("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"method": "PUT"})
	})
	hts.Router.DELETE("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"method": "DELETE"})
	})

	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := hts.SetupRequest(method, "/test")
			req.Header.Set("Origin", "https://example.com")
			hts.ExecuteRequest(req)

			hts.AssertResponseStatus(http.StatusOK)
			hts.AssertResponseHeader("Access-Control-Allow-Origin", "https://example.com")
			hts.AssertResponseContains(method)
		})
	}
}

// Test CORS preflight with different request methods
func TestCORS_PreflightDifferentMethods(t *testing.T) {
	hts := testutils.NewHTTPTestSuite(t)

	hts.Router.Use(CORS(86400))
	hts.Router.Handle("POST", "/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "POST success"})
	})
	hts.Router.Handle("PUT", "/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "PUT success"})
	})
	hts.Router.Handle("DELETE", "/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "DELETE success"})
	})

	requestMethods := []string{"POST", "PUT", "DELETE"}

	for _, requestMethod := range requestMethods {
		t.Run("Preflight_"+requestMethod, func(t *testing.T) {
			req := hts.SetupRequest(http.MethodOptions, "/test")
			req.Header.Set("Origin", "https://example.com")
			req.Header.Set("Access-Control-Request-Method", requestMethod)
			hts.ExecuteRequest(req)

			hts.AssertResponseStatus(http.StatusNoContent)
			hts.AssertResponseHeader("Access-Control-Allow-Origin", "https://example.com")
			hts.AssertResponseHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		})
	}
}
