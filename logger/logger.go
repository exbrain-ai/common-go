package logger

import (
	"context"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger interface defines the logging contract
type Logger interface {
	Debug(msg string, fields ...map[string]interface{})
	Info(msg string, fields ...map[string]interface{})
	Warn(msg string, fields ...map[string]interface{})
	Error(msg string, err error, fields ...map[string]interface{})
	Fatal(msg string, err error, fields ...map[string]interface{})
	WithFields(fields map[string]interface{}) Logger
	WithRequestID(requestID string) Logger
	WithService(service string) Logger
}

// ZapLogger implements the Logger interface using Zap
type ZapLogger struct {
	logger *zap.Logger
	level  zapcore.Level
}

// NewZapLogger creates a new Zap-based logger (deprecated - use NewZapLoggerFromConfig)
func NewZapLogger(level string) *ZapLogger {
	return NewZapLoggerFromConfig(level, "production")
}

// NewContextLogger creates a logger with request context
func (zl *ZapLogger) NewContextLogger(ctx context.Context, service string) Logger {
	// Extract request ID from context if available
	requestID := getRequestIDFromContext(ctx)

	// Create logger with service and request context
	fields := []zap.Field{
		zap.String("service", service),
	}

	if requestID != "" {
		fields = append(fields, zap.String("requestId", requestID))
	}

	return &ZapContextLogger{
		logger: zl.logger.With(fields...),
		level:  zl.level,
	}
}

// NewContextLogger creates a logger with request context (standalone function)
func NewContextLogger(ctx context.Context, service string) Logger {
	// Create a new ZapLogger instance
	zapLogger := NewFromEnv(service)

	// Extract request ID from context if available
	requestID := getRequestIDFromContext(ctx)

	// Create logger with service and request context
	fields := []zap.Field{
		zap.String("service", service),
	}

	if requestID != "" {
		fields = append(fields, zap.String("requestId", requestID))
	}

	// Cast to ZapLogger to access the underlying zap logger
	if zl, ok := zapLogger.(*ZapLogger); ok {
		return &ZapContextLogger{
			logger: zl.logger.With(fields...),
			level:  zl.level,
		}
	}

	// Fallback to basic logger
	return zapLogger
}

// Debug logs a debug message
func (zl *ZapLogger) Debug(message string, fields ...map[string]interface{}) {
	if zl.level <= zapcore.DebugLevel {
		zl.logger.Debug(message, convertFields(fields...)...)
	}
}

// Info logs an info message
func (zl *ZapLogger) Info(message string, fields ...map[string]interface{}) {
	if zl.level <= zapcore.InfoLevel {
		zl.logger.Info(message, convertFields(fields...)...)
	}
}

// Warn logs a warning message
func (zl *ZapLogger) Warn(message string, fields ...map[string]interface{}) {
	if zl.level <= zapcore.WarnLevel {
		zl.logger.Warn(message, convertFields(fields...)...)
	}
}

// Error logs an error message
func (zl *ZapLogger) Error(message string, err error, fields ...map[string]interface{}) {
	if zl.level <= zapcore.ErrorLevel {
		allFields := convertFields(fields...)
		if err != nil {
			allFields = append(allFields, zap.Error(err))
		}
		zl.logger.Error(message, allFields...)
	}
}

// Fatal logs a fatal message and exits
func (zl *ZapLogger) Fatal(message string, err error, fields ...map[string]interface{}) {
	allFields := convertFields(fields...)
	if err != nil {
		allFields = append(allFields, zap.Error(err))
	}
	zl.logger.Fatal(message, allFields...)
}

// Sync flushes any buffered log entries
func (zl *ZapLogger) Sync() error {
	return zl.logger.Sync()
}

// WithFields creates a new logger with additional fields
func (zl *ZapLogger) WithFields(fields map[string]interface{}) Logger {
	zapFields := convertFields(fields)
	return &ZapLogger{
		logger: zl.logger.With(zapFields...),
		level:  zl.level,
	}
}

// WithRequestID creates a new logger with request ID
func (zl *ZapLogger) WithRequestID(requestID string) Logger {
	return &ZapLogger{
		logger: zl.logger.With(zap.String("requestId", requestID)),
		level:  zl.level,
	}
}

// WithService creates a new logger with service name
func (zl *ZapLogger) WithService(service string) Logger {
	return &ZapLogger{
		logger: zl.logger.With(zap.String("service", service)),
		level:  zl.level,
	}
}

// ZapContextLogger implements Logger for request context
type ZapContextLogger struct {
	logger *zap.Logger
	level  zapcore.Level
}

// Debug logs a debug message
func (zcl *ZapContextLogger) Debug(message string, fields ...map[string]interface{}) {
	if zcl.level <= zapcore.DebugLevel {
		zcl.logger.Debug(message, convertFields(fields...)...)
	}
}

// Info logs an info message
func (zcl *ZapContextLogger) Info(message string, fields ...map[string]interface{}) {
	if zcl.level <= zapcore.InfoLevel {
		zcl.logger.Info(message, convertFields(fields...)...)
	}
}

// Warn logs a warning message
func (zcl *ZapContextLogger) Warn(message string, fields ...map[string]interface{}) {
	if zcl.level <= zapcore.WarnLevel {
		zcl.logger.Warn(message, convertFields(fields...)...)
	}
}

// Error logs an error message
func (zcl *ZapContextLogger) Error(message string, err error, fields ...map[string]interface{}) {
	if zcl.level <= zapcore.ErrorLevel {
		allFields := convertFields(fields...)
		if err != nil {
			allFields = append(allFields, zap.Error(err))
		}
		zcl.logger.Error(message, allFields...)
	}
}

// Fatal logs a fatal message and exits
func (zcl *ZapContextLogger) Fatal(message string, err error, fields ...map[string]interface{}) {
	allFields := convertFields(fields...)
	if err != nil {
		allFields = append(allFields, zap.Error(err))
	}
	zcl.logger.Fatal(message, allFields...)
}

// Sync flushes any buffered log entries
func (zcl *ZapContextLogger) Sync() error {
	return zcl.logger.Sync()
}

// WithFields creates a new logger with additional fields
func (zcl *ZapContextLogger) WithFields(fields map[string]interface{}) Logger {
	zapFields := convertFields(fields)
	return &ZapContextLogger{
		logger: zcl.logger.With(zapFields...),
		level:  zcl.level,
	}
}

// WithRequestID creates a new logger with request ID
func (zcl *ZapContextLogger) WithRequestID(requestID string) Logger {
	return &ZapContextLogger{
		logger: zcl.logger.With(zap.String("requestId", requestID)),
		level:  zcl.level,
	}
}

// WithService creates a new logger with service name
func (zcl *ZapContextLogger) WithService(service string) Logger {
	return &ZapContextLogger{
		logger: zcl.logger.With(zap.String("service", service)),
		level:  zcl.level,
	}
}

// Helper functions

// convertFields converts map[string]interface{} to zap.Field slice
func convertFields(fields ...map[string]interface{}) []zap.Field {
	var zapFields []zap.Field

	for _, fieldMap := range fields {
		for key, value := range fieldMap {
			zapFields = append(zapFields, zap.Any(key, value))
		}
	}

	return zapFields
}

// getRequestIDFromContext extracts request ID from context
func getRequestIDFromContext(ctx context.Context) string {
	if requestID, ok := ctx.Value("requestId").(string); ok {
		return requestID
	}
	return ""
}

// NewZapLoggerFromConfig creates a logger from configuration
func NewZapLoggerFromConfig(level string, environment string) *ZapLogger {
	// Configure based on environment
	var config zap.Config

	if environment == "development" || environment == "local" {
		// Development: more readable console output
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		config.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(time.RFC3339)
	} else {
		// Production: JSON output for log aggregation
		config = zap.NewProductionConfig()
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		config.EncoderConfig.LevelKey = "level"
		config.EncoderConfig.MessageKey = "message"
		config.EncoderConfig.CallerKey = "caller"
		config.EncoderConfig.StacktraceKey = "stacktrace"
		config.EncoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
	}

	// Set log level
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}
	config.Level = zap.NewAtomicLevelAt(zapLevel)

	// Build logger
	logger, err := config.Build()
	if err != nil {
		// Fallback to basic logger
		logger = zap.NewNop()
	}

	return &ZapLogger{
		logger: logger,
		level:  zapLevel,
	}
}

// LogLevel represents the logging level
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

// String returns the string representation of LogLevel
func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// ParseLogLevel parses a string to LogLevel
func ParseLogLevel(level string) LogLevel {
	switch level {
	case "debug", "DEBUG":
		return DEBUG
	case "info", "INFO":
		return INFO
	case "warn", "WARN", "warning", "WARNING":
		return WARN
	case "error", "ERROR":
		return ERROR
	default:
		return INFO
	}
}

// New creates a new logger instance (compatibility function)
func New(level LogLevel, service string) Logger {
	levelStr := level.String()
	zapLogger := NewZapLoggerFromConfig(levelStr, "production")
	return zapLogger.WithService(service)
}

// NewFromEnv creates a logger from environment variables
func NewFromEnv(service string) Logger {
	levelStr := os.Getenv("LOG_LEVEL")
	if levelStr == "" {
		levelStr = "info"
	}
	return New(ParseLogLevel(levelStr), service)
}

// Context keys for request ID and other context values
type contextKey string

const (
	RequestIDKey contextKey = "requestId"
	LoggerKey    contextKey = "logger"
)

// FromContext extracts logger from context
func FromContext(ctx context.Context) Logger {
	if logger, ok := ctx.Value(LoggerKey).(Logger); ok {
		return logger
	}
	return NewFromEnv("unknown")
}

// WithContext adds logger to context
func WithContext(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, LoggerKey, logger)
}

// WithRequestID adds request ID to context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, RequestIDKey, requestID)
}

// GetRequestID extracts request ID from context
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(RequestIDKey).(string); ok {
		return requestID
	}
	return ""
}

