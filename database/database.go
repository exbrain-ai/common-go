package database

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/medbai2/common-go/errors"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// AuthType represents the authentication method
type AuthType string

const (
	AuthTypePassword AuthType = "password" // Password-based authentication (Onebox)
	AuthTypeIAM     AuthType = "iam"       // IAM-based authentication (GCP)
)

// Config represents database configuration
type Config struct {
	Driver          string
	Host            string
	Port            int
	Name            string
	User            string
	Password        string
	AuthType        AuthType // Explicit authentication type: "password" or "iam"
	SSLMode         string
	SchemaAutoApply bool
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// buildDSN builds the PostgreSQL DSN string
// Handles both password-based and IAM-based authentication based on AuthType
func buildDSN(cfg Config) string {
	password := cfg.Password
	if cfg.AuthType == AuthTypeIAM {
		// IAM authentication: explicitly empty password
		// Cloud SQL Proxy will handle IAM token exchange
		password = ""
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
	
	return dsn
}

// New creates a new GORM database connection
// Supports both password-based (Onebox) and IAM-based (GCP) authentication
func New(cfg Config) (*gorm.DB, error) {
	// Validate AuthType
	if cfg.AuthType == "" {
		// Default to password auth if not specified (backward compatibility)
		cfg.AuthType = AuthTypePassword
	}
	if cfg.AuthType != AuthTypePassword && cfg.AuthType != AuthTypeIAM {
		return nil, errors.Wrap(fmt.Errorf("invalid auth type: %s (must be 'password' or 'iam')", cfg.AuthType), errors.ErrCodeDatabaseError, "invalid authentication configuration")
	}

	// Validate configuration based on auth type
	if cfg.AuthType == AuthTypeIAM && cfg.Password != "" {
		log.Printf("Warning: Password provided but using IAM authentication. Password will be ignored.")
	}
	if cfg.AuthType == AuthTypePassword && cfg.Password == "" {
		return nil, errors.Wrap(fmt.Errorf("password authentication requires a password"), errors.ErrCodeDatabaseError, "invalid authentication configuration")
	}

	dsn := buildDSN(cfg)

	// Log authentication mode for debugging
	if cfg.AuthType == AuthTypeIAM {
		log.Printf("Using IAM authentication for user: %s", cfg.User)
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
