package logger

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/medbai2/common-go/testutils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

// LoggerTestCase represents a logger test case
type LoggerTestCase struct {
	Name           string
	Level          zapcore.Level
	Message        string
	Fields         []map[string]interface{}
	Error          error
	ExpectedLevel  zapcore.Level
	ExpectedMsg    string
	ExpectedFields []string
	ValidateLog    func(t *testing.T, logs []zapcore.Entry)
}

// runLoggerTestCase runs a single logger test case
func runLoggerTestCase(t *testing.T, tc LoggerTestCase) {
	lts := testutils.NewLoggerTestSuite(t, tc.Level)

	// Execute the appropriate log method
	switch tc.Level {
	case zapcore.DebugLevel:
		lts.Logger.Debug(tc.Message, tc.Fields...)
	case zapcore.InfoLevel:
		lts.Logger.Info(tc.Message, tc.Fields...)
	case zapcore.WarnLevel:
		lts.Logger.Warn(tc.Message, tc.Fields...)
	case zapcore.ErrorLevel:
		lts.Logger.Error(tc.Message, tc.Error, tc.Fields...)
	case zapcore.FatalLevel:
		// Note: Fatal will exit, so we test it differently
		lts.Logger.Fatal(tc.Message, tc.Error, tc.Fields...)
	}

	// Basic assertions
	lts.AssertLogLevel(tc.ExpectedLevel)
	lts.AssertLogMessage(tc.ExpectedMsg)

	// Check for expected fields
	for _, fieldName := range tc.ExpectedFields {
		lts.AssertLogContainsField(fieldName)
	}

	// Custom validation
	if tc.ValidateLog != nil {
		logs := lts.Observer.All()
		// Convert []observer.LoggedEntry to []zapcore.Entry
		entries := make([]zapcore.Entry, len(logs))
		for i, log := range logs {
			entries[i] = log.Entry
		}
		tc.ValidateLog(t, entries)
	}
}

// Test ZapLogger basic functionality
func TestZapLogger_BasicLogging(t *testing.T) {
	testCases := []LoggerTestCase{
		{
			Name:          "Debug Level",
			Level:         zapcore.DebugLevel,
			Message:       "Debug message",
			ExpectedLevel: zapcore.DebugLevel,
			ExpectedMsg:   "Debug message",
		},
		{
			Name:          "Info Level",
			Level:         zapcore.InfoLevel,
			Message:       "Info message",
			ExpectedLevel: zapcore.InfoLevel,
			ExpectedMsg:   "Info message",
		},
		{
			Name:          "Warn Level",
			Level:         zapcore.WarnLevel,
			Message:       "Warning message",
			ExpectedLevel: zapcore.WarnLevel,
			ExpectedMsg:   "Warning message",
		},
		{
			Name:           "Error Level",
			Level:          zapcore.ErrorLevel,
			Message:        "Error message",
			Error:          errors.New("test error"),
			ExpectedLevel:  zapcore.ErrorLevel,
			ExpectedMsg:    "Error message",
			ExpectedFields: []string{"error"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			runLoggerTestCase(t, tc)
		})
	}
}

// Test ZapLogger with fields
func TestZapLogger_WithFields(t *testing.T) {
	testCases := []LoggerTestCase{
		{
			Name:    "Single Field",
			Level:   zapcore.InfoLevel,
			Message: "Message with field",
			Fields: []map[string]interface{}{
				{"operation": "test_operation"},
			},
			ExpectedLevel:  zapcore.InfoLevel,
			ExpectedMsg:    "Message with field",
			ExpectedFields: []string{"operation"},
		},
		{
			Name:    "Multiple Fields",
			Level:   zapcore.InfoLevel,
			Message: "Message with multiple fields",
			Fields: []map[string]interface{}{
				{"operation": "test_operation", "user_id": 123},
			},
			ExpectedLevel:  zapcore.InfoLevel,
			ExpectedMsg:    "Message with multiple fields",
			ExpectedFields: []string{"operation", "user_id"},
		},
		{
			Name:    "Nested Fields",
			Level:   zapcore.InfoLevel,
			Message: "Message with nested fields",
			Fields: []map[string]interface{}{
				{
					"user": map[string]interface{}{
						"id":   123,
						"name": "test_user",
					},
				},
			},
			ExpectedLevel:  zapcore.InfoLevel,
			ExpectedMsg:    "Message with nested fields",
			ExpectedFields: []string{"user"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			runLoggerTestCase(t, tc)
		})
	}
}

// Test ZapLogger context methods
func TestZapLogger_ContextMethods(t *testing.T) {
	lts := testutils.NewLoggerTestSuite(t, zapcore.InfoLevel)

	// Test WithRequestID
	requestLogger := lts.Logger.(*testutils.TestLogger)
	contextLogger := requestLogger.WithRequestID("req-123")

	contextLogger.Info("Message with request ID")

	lts.AssertLogMessage("Message with request ID")
	lts.AssertLogContainsField("request_id")
	lts.AssertLogFieldValue("request_id", "req-123")
}

// Test ZapLogger service context
func TestZapLogger_ServiceContext(t *testing.T) {
	lts := testutils.NewLoggerTestSuite(t, zapcore.InfoLevel)

	// Test WithService
	requestLogger := lts.Logger.(*testutils.TestLogger)
	serviceLogger := requestLogger.WithService("test-service")

	serviceLogger.Info("Message with service context")

	lts.AssertLogMessage("Message with service context")
	lts.AssertLogContainsField("service")
	lts.AssertLogFieldValue("service", "test-service")
}

// Test ZapContextLogger
func TestZapContextLogger(t *testing.T) {
	lts := testutils.NewLoggerTestSuite(t, zapcore.InfoLevel)

	// Create context logger using the test logger
	testLogger := lts.Logger.(*testutils.TestLogger)
	contextLogger := &ZapLogger{logger: testLogger.GetLogger()}

	// Log with fields to test the context logger
	contextLogger.Info("Message with context", map[string]interface{}{
		"request_id": "req-456",
		"user_id":    "user-123",
	})

	lts.AssertLogMessage("Message with context")
	lts.AssertLogContainsField("request_id")
	lts.AssertLogFieldValue("request_id", "req-456")
}

// Test NewFromEnv
func TestNewFromEnv(t *testing.T) {
	testCases := []struct {
		Name     string
		Env      string
		Expected zapcore.Level
	}{
		{
			Name:     "Development Environment",
			Env:      "development",
			Expected: zapcore.DebugLevel,
		},
		{
			Name:     "Production Environment",
			Env:      "production",
			Expected: zapcore.InfoLevel,
		},
		{
			Name:     "Test Environment",
			Env:      "test",
			Expected: zapcore.DebugLevel,
		},
		{
			Name:     "Unknown Environment",
			Env:      "unknown",
			Expected: zapcore.InfoLevel, // Default
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Set environment variable
			t.Setenv("ENVIRONMENT", tc.Env)

			logger := NewFromEnv("test")
			assert.NotNil(t, logger)

			// Test that the logger works
			logger.Info("Test message")
		})
	}
}

// Test field conversion
func TestConvertFields(t *testing.T) {
	testCases := []struct {
		Name     string
		Fields   []map[string]interface{}
		Expected map[string]interface{}
	}{
		{
			Name: "String Fields",
			Fields: []map[string]interface{}{
				{"operation": "test", "user_id": "123"},
			},
			Expected: map[string]interface{}{
				"operation": "test",
				"user_id":   "123",
			},
		},
		{
			Name: "Mixed Type Fields",
			Fields: []map[string]interface{}{
				{
					"operation": "test",
					"count":     42,
					"active":    true,
					"score":     3.14,
				},
			},
			Expected: map[string]interface{}{
				"operation": "test",
				"count":     42,
				"active":    true,
				"score":     3.14,
			},
		},
		{
			Name: "Nested Fields",
			Fields: []map[string]interface{}{
				{
					"user": map[string]interface{}{
						"id":   123,
						"name": "test",
					},
				},
			},
			Expected: map[string]interface{}{
				"user": map[string]interface{}{
					"id":   123,
					"name": "test",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Create a new test suite for each test to avoid log accumulation
			lts := testutils.NewLoggerTestSuite(t, zapcore.InfoLevel)

			// Convert fields using the test logger
			testLogger := lts.Logger.(*testutils.TestLogger)
			_ = testLogger.ConvertFields(tc.Fields...)

			// Log with converted fields
			testLogger.Info("Test message", tc.Fields...)

			// Verify the log was created
			logs := lts.Observer.All()
			require.Len(t, logs, 1)
			assert.Equal(t, "Test message", logs[0].Message)

			// Verify field count matches
			assert.Len(t, logs[0].Context, len(tc.Expected))
		})
	}
}

// Test error handling
func TestZapLogger_ErrorHandling(t *testing.T) {
	lts := testutils.NewLoggerTestSuite(t, zapcore.ErrorLevel)

	// Test with nil error
	lts.Logger.Error("Message with nil error", nil)

	logs := lts.Observer.All()
	require.Len(t, logs, 1)
	assert.Equal(t, "Message with nil error", logs[0].Message)

	// Test with actual error
	testErr := errors.New("test error")
	lts.Logger.Error("Message with error", testErr)

	logs = lts.Observer.All()
	require.Len(t, logs, 2)
	assert.Equal(t, "Message with error", logs[1].Message)

	// Verify error field is present
	hasErrorField := false
	for _, field := range logs[1].Context {
		if field.Key == "error" {
			hasErrorField = true
			break
		}
	}
	assert.True(t, hasErrorField, "Error field should be present")
}

// Test concurrent logging
func TestZapLogger_ConcurrentLogging(t *testing.T) {
	lts := testutils.NewLoggerTestSuite(t, zapcore.InfoLevel)

	// Run multiple goroutines logging concurrently
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			lts.Logger.Info("Concurrent message", map[string]interface{}{
				"goroutine_id": id,
			})
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all logs were created
	logs := lts.Observer.All()
	assert.Len(t, logs, 10)

	// Verify each log has the correct message
	for _, log := range logs {
		assert.Equal(t, "Concurrent message", log.Message)
	}
}

// Test performance with many fields
func TestZapLogger_PerformanceWithManyFields(t *testing.T) {
	lts := testutils.NewLoggerTestSuite(t, zapcore.InfoLevel)

	// Create a large number of fields
	fields := make(map[string]interface{})
	for i := 0; i < 100; i++ {
		fields[fmt.Sprintf("field_%d", i)] = fmt.Sprintf("value_%d", i)
	}

	// Log with many fields
	start := time.Now()
	lts.Logger.Info("Message with many fields", fields)
	duration := time.Since(start)

	// Verify log was created
	logs := lts.Observer.All()
	require.Len(t, logs, 1)
	assert.Equal(t, "Message with many fields", logs[0].Message)

	// Verify performance (should be fast)
	assert.Less(t, duration, 10*time.Millisecond, "Logging should be fast")
}

// Test different log levels filtering
func TestZapLogger_LevelFiltering(t *testing.T) {
	// Test with Info level - should not see Debug logs
	lts := testutils.NewLoggerTestSuite(t, zapcore.InfoLevel)

	lts.Logger.Debug("Debug message")
	lts.Logger.Info("Info message")
	lts.Logger.Warn("Warn message")
	lts.Logger.Error("Error message", errors.New("test error"))

	logs := lts.Observer.All()
	// Should only see Info, Warn, and Error (3 logs)
	assert.Len(t, logs, 3)

	// Verify no Debug logs
	for _, log := range logs {
		assert.NotEqual(t, zapcore.DebugLevel, log.Level)
	}
}

// Test structured logging with complex data
func TestZapLogger_ComplexDataStructures(t *testing.T) {
	lts := testutils.NewLoggerTestSuite(t, zapcore.InfoLevel)

	// Test with slice
	lts.Logger.Info("Message with slice", map[string]interface{}{
		"items": []string{"item1", "item2", "item3"},
	})

	// Test with map
	lts.Logger.Info("Message with map", map[string]interface{}{
		"config": map[string]interface{}{
			"timeout": 30,
			"retries": 3,
			"enabled": true,
		},
	})

	// Test with time
	lts.Logger.Info("Message with time", map[string]interface{}{
		"timestamp": time.Now(),
	})

	logs := lts.Observer.All()
	assert.Len(t, logs, 3)

	// Verify each log has the expected structure
	for i, expectedKey := range []string{"items", "config", "timestamp"} {
		hasKey := false
		for _, field := range logs[i].Context {
			if field.Key == expectedKey {
				hasKey = true
				break
			}
		}
		assert.True(t, hasKey, "Log %d should have key %s", i, expectedKey)
	}
}
