package middleware

import (
	"strings"

	"github.com/exbrain-ai/common-go/logger"
	"github.com/google/uuid"

	"github.com/gin-gonic/gin"
)

// PropagateRequestID bridges Gin request-id middleware into:
// - Go context (logger.WithRequestID)
// - Gin context key "requestId" (used by common-go Logger formatter)
//
// Expected ordering (Hello pattern):
//
//	router.Use(requestid.New())
//	router.Use(middleware.PropagateRequestID())
//
// This middleware is defensive and will generate a request ID if missing.
func PropagateRequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		// gin-contrib/requestid stores the request ID under "requestid" (lowercase)
		// Check this first before falling back to header
		var requestID string
		if val, exists := c.Get("requestid"); exists {
			if id, ok := val.(string); ok {
				requestID = strings.TrimSpace(id)
			}
		}
		// Fallback: try to get from header directly (if client sent it)
		if requestID == "" {
			requestID = strings.TrimSpace(c.GetHeader("X-Request-ID"))
		}

		if requestID == "" {
			requestID = uuid.NewString()
		}

		// Put request ID into Go context for structured logging.
		ctx := logger.WithRequestID(c.Request.Context(), requestID)
		c.Request = c.Request.WithContext(ctx)

		// Put request ID into Gin context for the common-go Logger formatter.
		c.Set("requestId", requestID)

		// Also return it to the caller for easier debugging/correlation.
		c.Header("X-Request-ID", requestID)

		c.Next()
	}
}
