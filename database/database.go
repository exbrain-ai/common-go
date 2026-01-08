package database

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/exbrain-ai/common-go/errors"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// AuthType represents the authentication method
type AuthType string

const (
	AuthTypePassword AuthType = "password" // Password-based authentication (Onebox)
	AuthTypeIAM     AuthType = "iam"       // IAM-based authentication (GCP)
	AuthTypeAzureAD AuthType = "azuread"   // Azure AD authentication (Azure PostgreSQL)
)

// Azure AD token resource for PostgreSQL
const azurePostgreSQLResourceID = "https://ossrdbms-aad.database.windows.net"

// Config represents database configuration
type Config struct {
	Driver          string
	Host            string
	Port            int
	Name            string
	User            string
	Password        string
	AuthType        AuthType // Explicit authentication type: "password", "iam", or "azuread"
	SSLMode         string
	SchemaAutoApply bool
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
	// Azure AD specific configuration
	AzureManagedIdentityClientID string // Managed identity client ID for Azure AD auth
}

// tokenCache caches Azure AD tokens with expiration
type tokenCache struct {
	token     string
	expiresAt time.Time
	mu        sync.RWMutex
}

var globalTokenCache = &tokenCache{}

// getAzureADToken gets an Azure AD token for PostgreSQL authentication
// Uses managed identity (Workload Identity) to acquire the token
// If clientID is empty, the Azure SDK will auto-detect the managed identity from the pod's
// service account annotation (azure.workload.identity/client-id) when running in AKS with Workload Identity enabled
func getAzureADToken(ctx context.Context, clientID string) (string, error) {
	// Check cache first
	globalTokenCache.mu.RLock()
	if globalTokenCache.token != "" && time.Now().Before(globalTokenCache.expiresAt.Add(-5*time.Minute)) {
		// Token is still valid (with 5 minute buffer)
		token := globalTokenCache.token
		globalTokenCache.mu.RUnlock()
		return token, nil
	}
	globalTokenCache.mu.RUnlock()

	// Acquire new token
	globalTokenCache.mu.Lock()
	defer globalTokenCache.mu.Unlock()

	// Double-check after acquiring lock
	if globalTokenCache.token != "" && time.Now().Before(globalTokenCache.expiresAt.Add(-5*time.Minute)) {
		return globalTokenCache.token, nil
	}

	// Create credential options
	// If clientID is empty, pass nil to auto-detect from pod's workload identity
	var credOptions *azidentity.ManagedIdentityCredentialOptions
	if clientID != "" {
		credOptions = &azidentity.ManagedIdentityCredentialOptions{
			ID: azidentity.ClientID(clientID),
		}
		log.Printf("Using explicit managed identity client ID: %s", clientID)
	} else {
		log.Printf("No client ID provided, will auto-detect managed identity from pod's workload identity")
	}

	// Create managed identity credential
	// If credOptions is nil, SDK auto-detects from pod's service account annotation
	cred, err := azidentity.NewManagedIdentityCredential(credOptions)
	if err != nil {
		if clientID == "" {
			return "", fmt.Errorf("failed to auto-detect managed identity credential (ensure pod has workload identity configured with azure.workload.identity/client-id annotation): %w", err)
		}
		return "", fmt.Errorf("failed to create managed identity credential with client ID %s: %w", clientID, err)
	}

	// Get token for PostgreSQL
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{azurePostgreSQLResourceID + "/.default"},
	})
	if err != nil {
		return "", fmt.Errorf("failed to get Azure AD token: %w", err)
	}

	// Cache the token
	globalTokenCache.token = token.Token
	globalTokenCache.expiresAt = token.ExpiresOn

	log.Printf("Acquired Azure AD token (expires at: %v)", token.ExpiresOn)
	return token.Token, nil
}

// buildDSN builds the PostgreSQL DSN string
// Handles password-based, IAM-based (GCP), and Azure AD authentication based on AuthType
func buildDSN(ctx context.Context, cfg Config) (string, error) {
	password := cfg.Password
	
	if cfg.AuthType == AuthTypeIAM {
		// IAM authentication: explicitly empty password
		// Cloud SQL Proxy will handle IAM token exchange
		password = ""
	} else if cfg.AuthType == AuthTypeAzureAD {
		// Azure AD authentication: get token from managed identity
		// AzureManagedIdentityClientID is optional - if empty, SDK will auto-detect from pod's workload identity
		token, err := getAzureADToken(ctx, cfg.AzureManagedIdentityClientID)
		if err != nil {
			return "", fmt.Errorf("failed to get Azure AD token: %w", err)
		}
		password = token
		
		// For Azure AD, username should be the managed identity client ID if provided
		// If not provided, the database connection will use the auto-detected identity
		if cfg.User == "" && cfg.AzureManagedIdentityClientID != "" {
			cfg.User = cfg.AzureManagedIdentityClientID
		}
	}
	// Debug: Log the config values being used
	log.Printf("buildDSN - Host: %s, Port: %d, User: %s, Name: %s, SSLMode: %s",
		cfg.Host, cfg.Port, cfg.User, cfg.Name, cfg.SSLMode)
	
	// PostgreSQL DSN format: Use postgres:// URL format for better special character handling
	// The postgres:// URL format properly handles special characters in username/password
	// Format: postgres://[user[:password]@][host][:port][/database][?parameters]
	userName := cfg.User
	dbName := cfg.Name
	
	// URL-encode special characters for postgres:// URL format
	// The postgres:// parser will decode these before sending to PostgreSQL
	if strings.Contains(userName, "@") {
		userName = strings.ReplaceAll(userName, "@", "%40")
	}
	if strings.Contains(userName, ":") {
		userName = strings.ReplaceAll(userName, ":", "%3A")
	}
	if strings.Contains(userName, "/") {
		userName = strings.ReplaceAll(userName, "/", "%2F")
	}
	if strings.Contains(userName, "?") {
		userName = strings.ReplaceAll(userName, "?", "%3F")
	}
	if strings.Contains(userName, "#") {
		userName = strings.ReplaceAll(userName, "#", "%23")
	}
	if strings.Contains(userName, "[") {
		userName = strings.ReplaceAll(userName, "[", "%5B")
	}
	if strings.Contains(userName, "]") {
		userName = strings.ReplaceAll(userName, "]", "%5D")
	}
	if strings.Contains(userName, " ") {
		userName = strings.ReplaceAll(userName, " ", "%20")
	}
	
	// URL-encode database name if needed
	if strings.Contains(dbName, "?") {
		dbName = strings.ReplaceAll(dbName, "?", "%3F")
	}
	if strings.Contains(dbName, "#") {
		dbName = strings.ReplaceAll(dbName, "#", "%23")
	}
	
	// Build postgres:// URL format DSN
	// For IAM auth, password is empty, so format is: postgres://user@host:port/db?sslmode=...
	// Use url.QueryEscape for proper URL encoding
	var dsn string
	if password == "" {
		dsn = fmt.Sprintf("postgres://%s@%s:%d/%s?sslmode=%s",
			userName, cfg.Host, cfg.Port, dbName, cfg.SSLMode)
	} else {
		// URL-encode password using proper URL encoding
		encodedPassword := url.QueryEscape(password)
		dsn = fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
			userName, encodedPassword, cfg.Host, cfg.Port, dbName, cfg.SSLMode)
	}
	
	log.Printf("buildDSN - URL-encoded username: %s", userName)
	
	// Security: never log DSNs because they can include secrets (passwords/tokens).
	log.Printf("buildDSN - dbname in DSN: '%s' (length: %d)", dbName, len(dbName))
	
	return dsn, nil
}

// New creates a new GORM database connection
// Supports both password-based (Onebox) and IAM-based (GCP) authentication
func New(cfg Config) (*gorm.DB, error) {
	// Validate AuthType
	if cfg.AuthType == "" {
		// Default to password auth if not specified (backward compatibility)
		cfg.AuthType = AuthTypePassword
	}
	if cfg.AuthType != AuthTypePassword && cfg.AuthType != AuthTypeIAM && cfg.AuthType != AuthTypeAzureAD {
		return nil, errors.Wrap(fmt.Errorf("invalid auth type: %s (must be 'password', 'iam', or 'azuread')", cfg.AuthType), errors.ErrCodeDatabaseError, "invalid authentication configuration")
	}

	// Validate configuration based on auth type
	if cfg.AuthType == AuthTypeIAM && cfg.Password != "" {
		log.Printf("Warning: Password provided but using IAM authentication. Password will be ignored.")
	}
	if cfg.AuthType == AuthTypeAzureAD && cfg.Password != "" {
		log.Printf("Warning: Password provided but using Azure AD authentication. Password will be ignored.")
	}
	if cfg.AuthType == AuthTypePassword && cfg.Password == "" {
		return nil, errors.Wrap(fmt.Errorf("password authentication requires a password"), errors.ErrCodeDatabaseError, "invalid authentication configuration")
	}
	// Note: AzureManagedIdentityClientID is optional for Azure AD auth
	// If not provided, the SDK will auto-detect from pod's workload identity (azure.workload.identity/client-id annotation)
	// Validation happens at token acquisition time, not here, to provide better error messages

	// Build DSN with context for Azure AD token acquisition
	ctx := context.Background()
	dsn, err := buildDSN(ctx, cfg)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to build database connection string")
	}

	// Log authentication mode for debugging
	if cfg.AuthType == AuthTypeIAM {
		log.Printf("Using IAM authentication for user: %s", cfg.User)
	} else if cfg.AuthType == AuthTypeAzureAD {
		log.Printf("Using Azure AD authentication for user: %s (managed identity: %s)", cfg.User, cfg.AzureManagedIdentityClientID)
	} else {
		log.Printf("Using password authentication for user: %s", cfg.User)
	}

	// Configure GORM
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	}

	db, err := gorm.Open(postgres.Open(dsn), gormConfig)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to connect to database")
	}

	// Get underlying sql.DB for connection pool configuration
	sqlDB, err := db.DB()
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to get underlying sql.DB")
	}

	// Configure connection pool
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)

	// Set connection lifetime - configuration already contains proper duration
	if cfg.ConnMaxLifetime > 0 {
		sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	}

	// Set connection idle time - configuration already contains proper duration
	if cfg.ConnMaxIdleTime > 0 {
		sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	}

	// Test connection
	if err := sqlDB.Ping(); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to ping database")
	}

	return db, nil
}

// HealthCheck performs a simple health check on the database
func HealthCheck(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "failed to get underlying sql.DB")
	}

	var result int
	err = sqlDB.QueryRow("SELECT 1").Scan(&result)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "health check failed")
	}
	return nil
}
