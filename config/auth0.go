package config

import "fmt"

// Auth0Config holds Auth0 configuration
type Auth0Config struct {
	Domain   string // Auth0 domain (e.g., "your-tenant.auth0.com")
	Audience string // API audience/identifier
	Enabled  bool   // Whether Auth0 validation is enabled
}

// Validate validates the Auth0 configuration
func (c *Auth0Config) Validate() error {
	if !c.Enabled {
		return nil // Skip validation if disabled
	}

	if c.Domain == "" {
		return fmt.Errorf("auth0 domain is required")
	}

	if c.Audience == "" {
		return fmt.Errorf("auth0 audience is required")
	}

	return nil
}

