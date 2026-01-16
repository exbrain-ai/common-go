package middleware

import (
	"regexp"
	"strings"

	"github.com/exbrain-ai/common-go/logger"
	"github.com/exbrain-ai/common-go/response"

	"github.com/gin-gonic/gin"
)

// permissionFormatRegex validates permission format: {app}:{feature}:{action}
// Matches lowercase letters, numbers, underscores, and colons
// Example: "hello:greeting:create", "hello:greeting:delete"
var permissionFormatRegex = regexp.MustCompile(`^[a-z0-9_:]+$`)

// RequireAuth checks if user is authenticated (X-User-ID header present)
// Returns 403 Forbidden if user is not authenticated
func RequireAuth(appLogger logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestLogger := logger.NewContextLogger(c.Request.Context(), "rbac-require-auth")

		// Check if X-User-ID header is present (user is authenticated)
		userID := strings.TrimSpace(c.GetHeader("X-User-ID"))
		if userID == "" {
			requestLogger.Warn("Authentication required but X-User-ID header missing", map[string]interface{}{
				"path":   c.Request.URL.Path,
				"method": c.Request.Method,
			})
			response.Forbidden(c, "Authentication required")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyRole checks if user has any of the specified roles
// Roles are extracted from X-User-Roles header (comma-separated)
// Returns 403 Forbidden if user doesn't have any of the required roles
func RequireAnyRole(appLogger logger.Logger, roles ...string) gin.HandlerFunc {
	if len(roles) == 0 {
		// No roles specified - allow all authenticated users
		return RequireAuth(appLogger)
	}

	return func(c *gin.Context) {
		requestLogger := logger.NewContextLogger(c.Request.Context(), "rbac-require-any-role")

		// First check authentication
		userID := strings.TrimSpace(c.GetHeader("X-User-ID"))
		if userID == "" {
			requestLogger.Warn("Authentication required but X-User-ID header missing", map[string]interface{}{
				"path":   c.Request.URL.Path,
				"method": c.Request.Method,
			})
			response.Forbidden(c, "Authentication required")
			c.Abort()
			return
		}

		// Extract roles from X-User-Roles header
		rolesHeader := strings.TrimSpace(c.GetHeader("X-User-Roles"))
		userRoles := parseCommaSeparated(rolesHeader)

		// Check if user has any of the required roles
		hasRole := false
		for _, requiredRole := range roles {
			for _, userRole := range userRoles {
				if userRole == requiredRole {
					hasRole = true
					break
				}
			}
			if hasRole {
				break
			}
		}

		if !hasRole {
			requestLogger.Warn("User does not have required role", map[string]interface{}{
				"user_id":        userID,
				"user_roles":     userRoles,
				"required_roles": roles,
				"path":           c.Request.URL.Path,
				"method":         c.Request.Method,
			})
			response.Forbidden(c, "Insufficient permissions: required role not found")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyPermission checks if user has any of the specified permissions
// Permissions are extracted from X-User-Permissions header (comma-separated)
// Validates permission format ({app}:{feature}:{action}) before use (defense in depth)
// Returns 403 Forbidden if user doesn't have any of the required permissions
func RequireAnyPermission(appLogger logger.Logger, permissions ...string) gin.HandlerFunc {
	if len(permissions) == 0 {
		// No permissions specified - allow all authenticated users
		return RequireAuth(appLogger)
	}

	return func(c *gin.Context) {
		requestLogger := logger.NewContextLogger(c.Request.Context(), "rbac-require-any-permission")

		// First check authentication
		userID := strings.TrimSpace(c.GetHeader("X-User-ID"))
		if userID == "" {
			requestLogger.Warn("Authentication required but X-User-ID header missing", map[string]interface{}{
				"path":   c.Request.URL.Path,
				"method": c.Request.Method,
			})
			response.Forbidden(c, "Authentication required")
			c.Abort()
			return
		}

		// Extract permissions from X-User-Permissions header
		permissionsHeader := strings.TrimSpace(c.GetHeader("X-User-Permissions"))
		userPermissions := parseCommaSeparated(permissionsHeader)

		// Validate permission format for all user permissions (defense in depth)
		validUserPermissions := []string{}
		for _, perm := range userPermissions {
			if !permissionFormatRegex.MatchString(perm) {
				requestLogger.Warn("Permission has invalid format, filtering out", map[string]interface{}{
					"user_id":    userID,
					"permission": perm,
					"reason":     "invalid format (does not match pattern {app}:{feature}:{action})",
				})
				continue
			}
			validUserPermissions = append(validUserPermissions, perm)
		}

		// Validate permission format for required permissions
		validRequiredPermissions := []string{}
		for _, perm := range permissions {
			if !permissionFormatRegex.MatchString(perm) {
				requestLogger.Warn("Required permission has invalid format, skipping", map[string]interface{}{
					"permission": perm,
					"reason":     "invalid format (does not match pattern {app}:{feature}:{action})",
				})
				continue
			}
			validRequiredPermissions = append(validRequiredPermissions, perm)
		}

		// Check if user has any of the required permissions
		hasPermission := false
		for _, requiredPerm := range validRequiredPermissions {
			for _, userPerm := range validUserPermissions {
				if userPerm == requiredPerm {
					hasPermission = true
					break
				}
			}
			if hasPermission {
				break
			}
		}

		if !hasPermission {
			requestLogger.Warn("User does not have required permission", map[string]interface{}{
				"user_id":              userID,
				"user_permissions":     validUserPermissions,
				"required_permissions": validRequiredPermissions,
				"path":                 c.Request.URL.Path,
				"method":               c.Request.Method,
			})
			response.Forbidden(c, "Insufficient permissions: required permission not found")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAllPermissions checks if user has all of the specified permissions
// Permissions are extracted from X-User-Permissions header (comma-separated)
// Validates permission format ({app}:{feature}:{action}) before use (defense in depth)
// Returns 403 Forbidden if user doesn't have all of the required permissions
func RequireAllPermissions(appLogger logger.Logger, permissions ...string) gin.HandlerFunc {
	if len(permissions) == 0 {
		// No permissions specified - allow all authenticated users
		return RequireAuth(appLogger)
	}

	return func(c *gin.Context) {
		requestLogger := logger.NewContextLogger(c.Request.Context(), "rbac-require-all-permissions")

		// First check authentication
		userID := strings.TrimSpace(c.GetHeader("X-User-ID"))
		if userID == "" {
			requestLogger.Warn("Authentication required but X-User-ID header missing", map[string]interface{}{
				"path":   c.Request.URL.Path,
				"method": c.Request.Method,
			})
			response.Forbidden(c, "Authentication required")
			c.Abort()
			return
		}

		// Extract permissions from X-User-Permissions header
		permissionsHeader := strings.TrimSpace(c.GetHeader("X-User-Permissions"))
		userPermissions := parseCommaSeparated(permissionsHeader)

		// Validate permission format for all user permissions (defense in depth)
		validUserPermissions := []string{}
		for _, perm := range userPermissions {
			if !permissionFormatRegex.MatchString(perm) {
				requestLogger.Warn("Permission has invalid format, filtering out", map[string]interface{}{
					"user_id":    userID,
					"permission": perm,
					"reason":     "invalid format (does not match pattern {app}:{feature}:{action})",
				})
				continue
			}
			validUserPermissions = append(validUserPermissions, perm)
		}

		// Validate permission format for required permissions
		validRequiredPermissions := []string{}
		for _, perm := range permissions {
			if !permissionFormatRegex.MatchString(perm) {
				requestLogger.Warn("Required permission has invalid format, skipping", map[string]interface{}{
					"permission": perm,
					"reason":     "invalid format (does not match pattern {app}:{feature}:{action})",
				})
				continue
			}
			validRequiredPermissions = append(validRequiredPermissions, perm)
		}

		// Check if user has all of the required permissions
		missingPermissions := []string{}
		for _, requiredPerm := range validRequiredPermissions {
			hasPermission := false
			for _, userPerm := range validUserPermissions {
				if userPerm == requiredPerm {
					hasPermission = true
					break
				}
			}
			if !hasPermission {
				missingPermissions = append(missingPermissions, requiredPerm)
			}
		}

		if len(missingPermissions) > 0 {
			requestLogger.Warn("User does not have all required permissions", map[string]interface{}{
				"user_id":              userID,
				"user_permissions":     validUserPermissions,
				"required_permissions": validRequiredPermissions,
				"missing_permissions":  missingPermissions,
				"path":                 c.Request.URL.Path,
				"method":               c.Request.Method,
			})
			response.Forbidden(c, "Insufficient permissions: missing required permissions")
			c.Abort()
			return
		}

		c.Next()
	}
}

// parseCommaSeparated parses a comma-separated string into a slice of trimmed strings
// Handles empty strings and whitespace
func parseCommaSeparated(s string) []string {
	if s == "" {
		return []string{}
	}

	parts := strings.Split(s, ",")
	result := []string{}
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// HasPermission checks if the permissions slice contains the specified permission
// This is a utility function for handlers and services to check permissions
// without requiring gin context. The permission check is case-sensitive and
// whitespace is trimmed from both the permission list and required permission.
//
// Example usage in handlers:
//
//	permissions := middleware.ParsePermissions(c.GetHeader("X-User-Permissions"))
//	if middleware.HasPermission(permissions, "hello:message:delete") {
//	    // User has delete permission
//	}
//
// Example usage in services:
//
//	if middleware.HasPermission(userPermissions, "hello:message:delete_any") {
//	    // Admin delete path
//	} else if middleware.HasPermission(userPermissions, "hello:message:delete_own") {
//	    // User delete path (ownership check required)
//	}
func HasPermission(permissions []string, requiredPermission string) bool {
	requiredPermission = strings.TrimSpace(requiredPermission)
	for _, perm := range permissions {
		if strings.TrimSpace(perm) == requiredPermission {
			return true
		}
	}
	return false
}

// HasAnyPermission checks if the permissions slice contains any of the specified permissions
// Returns true if at least one of the required permissions is found
func HasAnyPermission(permissions []string, requiredPermissions ...string) bool {
	for _, required := range requiredPermissions {
		if HasPermission(permissions, required) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if the permissions slice contains all of the specified permissions
// Returns true only if all required permissions are found
func HasAllPermissions(permissions []string, requiredPermissions ...string) bool {
	for _, required := range requiredPermissions {
		if !HasPermission(permissions, required) {
			return false
		}
	}
	return true
}

// ParsePermissions parses a comma-separated permissions string into a slice
// This is a convenience wrapper around parseCommaSeparated for permission strings
// Example: "hello:message:delete,hello:message:view" -> ["hello:message:delete", "hello:message:view"]
func ParsePermissions(permissionsHeader string) []string {
	return parseCommaSeparated(permissionsHeader)
}







