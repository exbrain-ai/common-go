package types

// Auth0User represents user information extracted from JWT token
type Auth0User struct {
	Sub   string // Auth0 user ID (unique identifier)
	Email string
	Name  string
}

// ContextKey is the key used to store Auth0User in Gin context
type ContextKey string

const (
	// Auth0UserKey is the Gin context key for Auth0 user
	Auth0UserKey ContextKey = "auth0_user"
)

