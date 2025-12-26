package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/medbai2/common-go/config"
	"github.com/medbai2/common-go/logger"
	"github.com/medbai2/common-go/response"
	"github.com/medbai2/common-go/types"
)

var (
	jwksCache *jwk.Cache
)

// init initializes the JWKS cache
func init() {
	cache := jwk.NewCache(context.Background())
	jwksCache = cache
}

// Auth0 validates Auth0 JWT tokens
// It extracts the Bearer token from the Authorization header,
// validates it against Auth0's JWKS, and stores user info in Gin context
func Auth0(cfg *config.Auth0Config, appLogger logger.Logger) gin.HandlerFunc {
	if !cfg.Enabled {
		// If Auth0 is disabled, return a no-op middleware
		return func(c *gin.Context) {
			c.Next()
		}
	}

	appLogger.Info("Auth0 middleware enabled", map[string]interface{}{
		"domain":   cfg.Domain,
		"audience": cfg.Audience,
	})

	return func(c *gin.Context) {
		requestLogger := logger.NewContextLogger(c.Request.Context(), "auth0-middleware")

		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			requestLogger.Warn("Missing Authorization header")
			response.Unauthorized(c, "Authorization header required")
			c.Abort()
			return
		}

		// Parse Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			requestLogger.Warn("Invalid Authorization header format")
			response.Unauthorized(c, "Bearer token required")
			c.Abort()
			return
		}

		tokenString := parts[1]

		// Validate token
		user, err := validateToken(tokenString, cfg, requestLogger)
		if err != nil {
			requestLogger.Warn("Token validation failed", map[string]interface{}{
				"error": err.Error(),
			})
			response.Unauthorized(c, "Invalid or expired token")
			c.Abort()
			return
		}

		// Store user in context
		c.Set(string(types.Auth0UserKey), user)
		requestLogger.Info("Auth0 token validated successfully", map[string]interface{}{
			"user_id": user.Sub,
			"email":   user.Email,
		})
		c.Next()
	}
}

// validateToken validates the JWT token against Auth0's JWKS
func validateToken(tokenString string, cfg *config.Auth0Config, appLogger logger.Logger) (*types.Auth0User, error) {
	// Build JWKS URL from config
	jwksURL := fmt.Sprintf("https://%s/.well-known/jwks.json", cfg.Domain)

	// Parse token without validation first to get the kid
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get key ID from token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid not found in token header")
		}

		// Fetch JWKS - try cache first, if not registered, fetch and register
		keySet, err := jwksCache.Get(context.Background(), jwksURL)
		if err != nil {
			// URL not registered in cache yet - fetch and register it
			keySet, err = jwk.Fetch(context.Background(), jwksURL)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
			}
			// Register the URL in cache for future use with auto-refresh
			if err := jwksCache.Register(jwksURL, jwk.WithMinRefreshInterval(15*time.Minute)); err != nil {
				appLogger.Warn("Failed to register JWKS URL in cache", map[string]interface{}{
					"error": err.Error(),
				})
			}
			// Refresh to populate cache with the fetched keyset
			if _, err := jwksCache.Refresh(context.Background(), jwksURL); err != nil {
				appLogger.Warn("Failed to refresh JWKS cache", map[string]interface{}{
					"error": err.Error(),
				})
			}
		}

		// Find the key with matching kid
		key, found := keySet.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("key with kid %s not found", kid)
		}

		// Get public key
		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			return nil, fmt.Errorf("failed to get raw key: %w", err)
		}

		return rawKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Validate claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validate audience
	aud, ok := claims["aud"].(string)
	if !ok {
		// Try array format
		audArray, ok := claims["aud"].([]interface{})
		if ok && len(audArray) > 0 {
			aud = audArray[0].(string)
		} else {
			return nil, fmt.Errorf("audience not found in token")
		}
	}

	if aud != cfg.Audience {
		return nil, fmt.Errorf("audience mismatch: expected %s, got %s", cfg.Audience, aud)
	}

	// Validate issuer
	iss, ok := claims["iss"].(string)
	if !ok {
		return nil, fmt.Errorf("issuer not found in token")
	}

	// Auth0 issuer format: https://<domain>/ (with trailing slash)
	// Handle both with and without trailing slash for compatibility
	expectedIss := fmt.Sprintf("https://%s/", cfg.Domain)
	expectedIssNoSlash := fmt.Sprintf("https://%s", cfg.Domain)
	if iss != expectedIss && iss != expectedIssNoSlash {
		return nil, fmt.Errorf("issuer mismatch: expected %s or %s, got %s", expectedIss, expectedIssNoSlash, iss)
	}

	// Extract user information
	sub, ok := claims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("sub (subject) not found in token")
	}

	email, _ := claims["email"].(string)
	name := extractNameFromClaims(claims)
	if name == "" {
		name = email
	}
	if name == "" {
		name = sub
	}

	return &types.Auth0User{
		Sub:   sub,
		Email: email,
		Name:  name,
	}, nil
}

// OptionalAuth0 validates Auth0 JWT tokens optionally
// Unlike Auth0(), this middleware does NOT require authentication:
//   - If a valid token is present, it validates and sets user info in context
//   - If no token is present, the request continues (handler can check GetAuth0User)
//   - If token is invalid, the request continues without user info (handler decides)
//
// This pattern is common for endpoints that support both authenticated and unauthenticated access.
// The handler should check GetAuth0User(c) to determine if user is authenticated.
func OptionalAuth0(cfg *config.Auth0Config, appLogger logger.Logger) gin.HandlerFunc {
	if !cfg.Enabled {
		// If Auth0 is disabled, return a no-op middleware
		return func(c *gin.Context) {
			c.Next()
		}
	}

	// Build JWKS URL
	jwksURL := fmt.Sprintf("https://%s/.well-known/jwks.json", cfg.Domain)

	return func(c *gin.Context) {
		requestLogger := logger.NewContextLogger(c.Request.Context(), "auth0-middleware-optional")

		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		// Parse Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.Next()
			return
		}

		tokenString := parts[1]

		// Try to validate the token - if validation fails, continue without user info
		user, err := validateTokenWithUserInfo(tokenString, cfg, jwksURL, requestLogger)
		if err != nil {
			// Log at Warn level so it's visible - this helps debug authentication issues
			requestLogger.Warn("Optional Auth0 token validation failed", map[string]interface{}{
				"error": err.Error(),
			})
			c.Next()
			return
		}

		// Token is valid - store user in context using the same key as required middleware
		c.Set(string(types.Auth0UserKey), user)
		requestLogger.Info("Auth0 token validated successfully (optional)", map[string]interface{}{
			"user_id": user.Sub,
			"email":   user.Email,
		})
		c.Next()
	}
}

// validateTokenWithUserInfo validates the JWT token and fetches user info if needed
// This is a more complete version that can fetch from userinfo endpoint
func validateTokenWithUserInfo(tokenString string, cfg *config.Auth0Config, jwksURL string, appLogger logger.Logger) (*types.Auth0User, error) {
	// Use shared validation logic
	user, err := validateToken(tokenString, cfg, appLogger)
	if err != nil {
		return nil, err
	}

	// If we have name and email, return early
	if user.Name != "" && user.Email != "" {
		return user, nil
	}

	// If no user info in token, try to fetch from userinfo endpoint
	// This is needed when access tokens don't contain user claims
	if user.Email == "" || user.Name == "" {
		userInfo, err := fetchUserInfo(tokenString, cfg.Domain, appLogger)
		if err != nil {
			appLogger.Debug("Failed to fetch userinfo, using token claims", map[string]interface{}{
				"error": err.Error(),
			})
			// Return what we have from token
			return user, nil
		}
		// Update with userinfo data
		if userInfo.Email != "" {
			user.Email = userInfo.Email
		}
		if userInfo.Name != "" {
			user.Name = userInfo.Name
		}
	}

	// Ensure we have a name (fallback to email or sub)
	if user.Name == "" {
		user.Name = user.Email
	}
	if user.Name == "" {
		user.Name = user.Sub
	}

	return user, nil
}

// extractNameFromClaims extracts user name from JWT claims with priority:
// name > given_name+family_name > nickname > email
func extractNameFromClaims(claims jwt.MapClaims) string {
	// Try name claim first
	if name, ok := claims["name"].(string); ok && name != "" {
		return name
	}

	// Try given_name + family_name (common for Google OAuth)
	givenName, _ := claims["given_name"].(string)
	familyName, _ := claims["family_name"].(string)
	if givenName != "" || familyName != "" {
		if givenName != "" && familyName != "" {
			return fmt.Sprintf("%s %s", givenName, familyName)
		}
		if givenName != "" {
			return givenName
		}
		return familyName
	}

	// Try nickname
	if nickname, ok := claims["nickname"].(string); ok && nickname != "" {
		return nickname
	}

	return ""
}

// fetchUserInfo fetches user information from Auth0's userinfo endpoint
// This is needed when access tokens don't contain user claims
func fetchUserInfo(accessToken, domain string, appLogger logger.Logger) (*types.Auth0User, error) {
	userinfoURL := fmt.Sprintf("https://%s/userinfo", domain)

	req, err := http.NewRequest("GET", userinfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Content-Type", "application/json")

	// Use HTTP client with timeout to prevent hanging requests
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var userInfo struct {
		Sub        string `json:"sub"`
		Email      string `json:"email"`
		Name       string `json:"name"`
		Nickname   string `json:"nickname"`
		GivenName  string `json:"given_name"`
		FamilyName string `json:"family_name"`
		Picture    string `json:"picture"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode userinfo response: %w", err)
	}

	// Extract name with priority: name > given_name+family_name > nickname > email > sub
	name := userInfo.Name
	if name == "" {
		if userInfo.GivenName != "" || userInfo.FamilyName != "" {
			if userInfo.GivenName != "" && userInfo.FamilyName != "" {
				name = fmt.Sprintf("%s %s", userInfo.GivenName, userInfo.FamilyName)
			} else if userInfo.GivenName != "" {
				name = userInfo.GivenName
			} else {
				name = userInfo.FamilyName
			}
		}
	}
	if name == "" {
		name = userInfo.Nickname
	}
	if name == "" {
		name = userInfo.Email
	}
	if name == "" {
		name = userInfo.Sub
	}

	return &types.Auth0User{
		Sub:   userInfo.Sub,
		Email: userInfo.Email,
		Name:  name,
	}, nil
}

// GetAuth0User extracts Auth0User from Gin context
// Returns nil if not found or not authenticated
func GetAuth0User(c *gin.Context) *types.Auth0User {
	user, exists := c.Get(string(types.Auth0UserKey))
	if !exists {
		return nil
	}

	auth0User, ok := user.(*types.Auth0User)
	if !ok {
		return nil
	}

	return auth0User
}
