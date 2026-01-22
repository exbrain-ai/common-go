package middleware

import (
	"net/http"
	"testing"

	"github.com/exbrain-ai/common-go/logger"
	"github.com/exbrain-ai/common-go/testutils"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRequireAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		headers        map[string]string
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "Authenticated user",
			headers: map[string]string{
				"X-User-ID": "google-oauth2|123",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Unauthenticated user",
			headers:        map[string]string{},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Authentication required",
		},
		{
			name: "Empty X-User-ID",
			headers: map[string]string{
				"X-User-ID": "",
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Authentication required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hts := testutils.NewHTTPTestSuite(t)
			appLogger := logger.New(logger.INFO, "test")

			hts.Router.Use(RequireAuth(appLogger))
			hts.Router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			req := hts.SetupRequest(http.MethodGet, "/test")
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			hts.ExecuteRequest(req)
			hts.AssertResponseStatus(tt.expectedStatus)

			if tt.expectedBody != "" {
				hts.AssertResponseContains(tt.expectedBody)
			}
		})
	}
}

func TestRequireAnyRole(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		headers        map[string]string
		requiredRoles  []string
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "User has required role",
			headers: map[string]string{
				"X-User-ID":    "google-oauth2|123",
				"X-User-Roles": "user,moderator",
			},
			requiredRoles:  []string{"user"},
			expectedStatus: http.StatusOK,
		},
		{
			name: "User has one of multiple required roles",
			headers: map[string]string{
				"X-User-ID":    "google-oauth2|123",
				"X-User-Roles": "user",
			},
			requiredRoles:  []string{"admin", "moderator", "user"},
			expectedStatus: http.StatusOK,
		},
		{
			name: "User does not have required role",
			headers: map[string]string{
				"X-User-ID":    "google-oauth2|123",
				"X-User-Roles": "user",
			},
			requiredRoles:  []string{"admin"},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Insufficient permissions: required role not found",
		},
		{
			name: "User has no roles",
			headers: map[string]string{
				"X-User-ID": "google-oauth2|123",
			},
			requiredRoles:  []string{"user"},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Insufficient permissions: required role not found",
		},
		{
			name:           "Unauthenticated user",
			headers:        map[string]string{},
			requiredRoles:  []string{"user"},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Authentication required",
		},
		{
			name: "No roles required (allows all authenticated)",
			headers: map[string]string{
				"X-User-ID": "google-oauth2|123",
			},
			requiredRoles:  []string{},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Roles with spaces",
			headers: map[string]string{
				"X-User-ID":    "google-oauth2|123",
				"X-User-Roles": "user, moderator, admin",
			},
			requiredRoles:  []string{"moderator"},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hts := testutils.NewHTTPTestSuite(t)
			appLogger := logger.New(logger.INFO, "test")

			hts.Router.Use(RequireAnyRole(appLogger, tt.requiredRoles...))
			hts.Router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			req := hts.SetupRequest(http.MethodGet, "/test")
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			hts.ExecuteRequest(req)
			hts.AssertResponseStatus(tt.expectedStatus)

			if tt.expectedBody != "" {
				hts.AssertResponseContains(tt.expectedBody)
			}
		})
	}
}

func TestRequireAnyPermission(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name                string
		headers             map[string]string
		requiredPermissions []string
		expectedStatus      int
		expectedBody        string
	}{
		{
			name: "User has required permission",
			headers: map[string]string{
				"X-User-ID":          "google-oauth2|123",
				"X-User-Permissions": "hello:greeting:create,hello:greeting:delete",
			},
			requiredPermissions: []string{"hello:greeting:create"},
			expectedStatus:      http.StatusOK,
		},
		{
			name: "User has one of multiple required permissions",
			headers: map[string]string{
				"X-User-ID":          "google-oauth2|123",
				"X-User-Permissions": "hello:greeting:create",
			},
			requiredPermissions: []string{"hello:greeting:delete", "hello:greeting:update", "hello:greeting:create"},
			expectedStatus:      http.StatusOK,
		},
		{
			name: "User does not have required permission",
			headers: map[string]string{
				"X-User-ID":          "google-oauth2|123",
				"X-User-Permissions": "hello:greeting:create",
			},
			requiredPermissions: []string{"hello:greeting:delete"},
			expectedStatus:      http.StatusForbidden,
			expectedBody:        "Insufficient permissions: required permission not found",
		},
		{
			name: "User has no permissions",
			headers: map[string]string{
				"X-User-ID": "google-oauth2|123",
			},
			requiredPermissions: []string{"hello:greeting:create"},
			expectedStatus:      http.StatusForbidden,
			expectedBody:        "Insufficient permissions: required permission not found",
		},
		{
			name:                "Unauthenticated user",
			headers:             map[string]string{},
			requiredPermissions: []string{"hello:greeting:create"},
			expectedStatus:      http.StatusForbidden,
			expectedBody:        "Authentication required",
		},
		{
			name: "No permissions required (allows all authenticated)",
			headers: map[string]string{
				"X-User-ID": "google-oauth2|123",
			},
			requiredPermissions: []string{},
			expectedStatus:      http.StatusOK,
		},
		{
			name: "Invalid permission format filtered out",
			headers: map[string]string{
				"X-User-ID":          "google-oauth2|123",
				"X-User-Permissions": "hello:greeting:create,INVALID_PERMISSION,hello:greeting:delete",
			},
			requiredPermissions: []string{"hello:greeting:create"},
			expectedStatus:      http.StatusOK, // Should still work with valid permissions
		},
		{
			name: "Permissions with spaces",
			headers: map[string]string{
				"X-User-ID":          "google-oauth2|123",
				"X-User-Permissions": "hello:greeting:create, hello:greeting:delete",
			},
			requiredPermissions: []string{"hello:greeting:delete"},
			expectedStatus:      http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hts := testutils.NewHTTPTestSuite(t)
			appLogger := logger.New(logger.INFO, "test")

			hts.Router.Use(RequireAnyPermission(appLogger, tt.requiredPermissions...))
			hts.Router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			req := hts.SetupRequest(http.MethodGet, "/test")
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			hts.ExecuteRequest(req)
			hts.AssertResponseStatus(tt.expectedStatus)

			if tt.expectedBody != "" {
				hts.AssertResponseContains(tt.expectedBody)
			}
		})
	}
}

func TestRequireAllPermissions(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name                string
		headers             map[string]string
		requiredPermissions []string
		expectedStatus      int
		expectedBody        string
	}{
		{
			name: "User has all required permissions",
			headers: map[string]string{
				"X-User-ID":          "google-oauth2|123",
				"X-User-Permissions": "hello:greeting:create,hello:greeting:delete,hello:greeting:update",
			},
			requiredPermissions: []string{"hello:greeting:create", "hello:greeting:delete"},
			expectedStatus:      http.StatusOK,
		},
		{
			name: "User missing one required permission",
			headers: map[string]string{
				"X-User-ID":          "google-oauth2|123",
				"X-User-Permissions": "hello:greeting:create",
			},
			requiredPermissions: []string{"hello:greeting:create", "hello:greeting:delete"},
			expectedStatus:      http.StatusForbidden,
			expectedBody:        "Insufficient permissions: missing required permissions",
		},
		{
			name: "User missing all required permissions",
			headers: map[string]string{
				"X-User-ID":          "google-oauth2|123",
				"X-User-Permissions": "hello:greeting:update",
			},
			requiredPermissions: []string{"hello:greeting:create", "hello:greeting:delete"},
			expectedStatus:      http.StatusForbidden,
			expectedBody:        "Insufficient permissions: missing required permissions",
		},
		{
			name: "User has no permissions",
			headers: map[string]string{
				"X-User-ID": "google-oauth2|123",
			},
			requiredPermissions: []string{"hello:greeting:create"},
			expectedStatus:      http.StatusForbidden,
			expectedBody:        "Insufficient permissions: missing required permissions",
		},
		{
			name:                "Unauthenticated user",
			headers:             map[string]string{},
			requiredPermissions: []string{"hello:greeting:create"},
			expectedStatus:      http.StatusForbidden,
			expectedBody:        "Authentication required",
		},
		{
			name: "No permissions required (allows all authenticated)",
			headers: map[string]string{
				"X-User-ID": "google-oauth2|123",
			},
			requiredPermissions: []string{},
			expectedStatus:      http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hts := testutils.NewHTTPTestSuite(t)
			appLogger := logger.New(logger.INFO, "test")

			hts.Router.Use(RequireAllPermissions(appLogger, tt.requiredPermissions...))
			hts.Router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			req := hts.SetupRequest(http.MethodGet, "/test")
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			hts.ExecuteRequest(req)
			hts.AssertResponseStatus(tt.expectedStatus)

			if tt.expectedBody != "" {
				hts.AssertResponseContains(tt.expectedBody)
			}
		})
	}
}

func TestPermissionFormatValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name        string
		permission  string
		shouldMatch bool
		description string
	}{
		{
			name:        "Valid permission format",
			permission:  "hello:greeting:create",
			shouldMatch: true,
			description: "Standard format with lowercase",
		},
		{
			name:        "Valid with numbers",
			permission:  "app1:feature2:action3",
			shouldMatch: true,
			description: "Contains numbers",
		},
		{
			name:        "Valid with underscores",
			permission:  "hello:greeting_create:delete",
			shouldMatch: true,
			description: "Contains underscores",
		},
		{
			name:        "Invalid uppercase",
			permission:  "Hello:Greeting:Create",
			shouldMatch: false,
			description: "Uppercase letters not allowed",
		},
		{
			name:        "Invalid with spaces",
			permission:  "hello:greeting:create delete",
			shouldMatch: false,
			description: "Spaces not allowed",
		},
		{
			name:        "Invalid with special chars",
			permission:  "hello:greeting:create!",
			shouldMatch: false,
			description: "Special characters not allowed",
		},
		{
			name:        "Invalid format missing colons",
			permission:  "hellogreetingcreate",
			shouldMatch: false,
			description: "Missing colons",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := permissionFormatRegex.MatchString(tt.permission)
			assert.Equal(t, tt.shouldMatch, matches, tt.description)
		})
	}
}

func TestHasPermission(t *testing.T) {
	tests := []struct {
		name               string
		permissions        []string
		requiredPermission string
		expected           bool
	}{
		{
			name:               "Permission found",
			permissions:        []string{"hello:message:delete", "hello:message:create"},
			requiredPermission: "hello:message:delete",
			expected:           true,
		},
		{
			name:               "Permission not found",
			permissions:        []string{"hello:message:create"},
			requiredPermission: "hello:message:delete",
			expected:           false,
		},
		{
			name:               "Empty permissions list",
			permissions:        []string{},
			requiredPermission: "hello:message:delete",
			expected:           false,
		},
		{
			name:               "Nil permissions list",
			permissions:        nil,
			requiredPermission: "hello:message:delete",
			expected:           false,
		},
		{
			name:               "Permission with whitespace trimmed",
			permissions:        []string{" hello:message:delete ", "hello:message:create"},
			requiredPermission: "hello:message:delete",
			expected:           true,
		},
		{
			name:               "Required permission with whitespace trimmed",
			permissions:        []string{"hello:message:delete", "hello:message:create"},
			requiredPermission: " hello:message:delete ",
			expected:           true,
		},
		{
			name:               "Case sensitive - no match",
			permissions:        []string{"Hello:Message:Delete"},
			requiredPermission: "hello:message:delete",
			expected:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasPermission(tt.permissions, tt.requiredPermission)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasAnyPermission(t *testing.T) {
	tests := []struct {
		name                string
		permissions         []string
		requiredPermissions []string
		expected            bool
	}{
		{
			name:                "Has first of multiple required",
			permissions:         []string{"hello:message:delete", "hello:message:create"},
			requiredPermissions: []string{"hello:message:delete", "hello:admin:manage"},
			expected:            true,
		},
		{
			name:                "Has second of multiple required",
			permissions:         []string{"hello:admin:manage"},
			requiredPermissions: []string{"hello:message:delete", "hello:admin:manage"},
			expected:            true,
		},
		{
			name:                "Has none of multiple required",
			permissions:         []string{"hello:message:view"},
			requiredPermissions: []string{"hello:message:delete", "hello:admin:manage"},
			expected:            false,
		},
		{
			name:                "Empty permissions",
			permissions:         []string{},
			requiredPermissions: []string{"hello:message:delete"},
			expected:            false,
		},
		{
			name:                "Empty required permissions",
			permissions:         []string{"hello:message:delete"},
			requiredPermissions: []string{},
			expected:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasAnyPermission(tt.permissions, tt.requiredPermissions...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasAllPermissions(t *testing.T) {
	tests := []struct {
		name                string
		permissions         []string
		requiredPermissions []string
		expected            bool
	}{
		{
			name:                "Has all required permissions",
			permissions:         []string{"hello:message:delete", "hello:message:create", "hello:admin:manage"},
			requiredPermissions: []string{"hello:message:delete", "hello:message:create"},
			expected:            true,
		},
		{
			name:                "Missing one required permission",
			permissions:         []string{"hello:message:delete"},
			requiredPermissions: []string{"hello:message:delete", "hello:message:create"},
			expected:            false,
		},
		{
			name:                "Missing all required permissions",
			permissions:         []string{"hello:message:view"},
			requiredPermissions: []string{"hello:message:delete", "hello:message:create"},
			expected:            false,
		},
		{
			name:                "Empty permissions",
			permissions:         []string{},
			requiredPermissions: []string{"hello:message:delete"},
			expected:            false,
		},
		{
			name:                "Empty required permissions",
			permissions:         []string{"hello:message:delete"},
			requiredPermissions: []string{},
			expected:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasAllPermissions(tt.permissions, tt.requiredPermissions...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParsePermissions(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected []string
	}{
		{
			name:     "Multiple permissions",
			header:   "hello:message:delete,hello:message:create",
			expected: []string{"hello:message:delete", "hello:message:create"},
		},
		{
			name:     "Permissions with spaces",
			header:   "hello:message:delete, hello:message:create, hello:admin:manage",
			expected: []string{"hello:message:delete", "hello:message:create", "hello:admin:manage"},
		},
		{
			name:     "Single permission",
			header:   "hello:message:delete",
			expected: []string{"hello:message:delete"},
		},
		{
			name:     "Empty header",
			header:   "",
			expected: []string{},
		},
		{
			name:     "Only whitespace",
			header:   "   ",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePermissions(tt.header)
			assert.Equal(t, tt.expected, result)
		})
	}
}
