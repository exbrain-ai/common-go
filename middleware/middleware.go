package middleware

import (
	"fmt"
	"net/http"

	"github.com/medbai2/common-go/logger"

	"github.com/gin-gonic/gin"
)

// Logger returns a gin.HandlerFunc for logging requests
func Logger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		// Create a structured log entry
		appLogger := logger.NewFromEnv("http-request")

		// Extract request ID if available
		requestID := ""
		if id, exists := param.Keys["requestId"]; exists {
			if idStr, ok := id.(string); ok {
				requestID = idStr
			}
		}

		// Log the request
		appLogger.Info("HTTP request completed", map[string]interface{}{
			"requestId":  requestID,
			"method":     param.Method,
			"url":        param.Path,
			"statusCode": param.StatusCode,
			"duration":   param.Latency.Milliseconds(),
			"userAgent":  param.Request.UserAgent(),
			"clientIP":   param.ClientIP,
		})

		return ""
	})
}

// CORS returns a gin.HandlerFunc for CORS configuration
func CORS(corsMaxAge int) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Set CORS headers
		if origin != "" {
			c.Header("Access-Control-Allow-Origin", origin)
		} else {
			c.Header("Access-Control-Allow-Origin", "*")
		}

		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
		c.Header("Access-Control-Max-Age", fmt.Sprintf("%d", corsMaxAge))

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
