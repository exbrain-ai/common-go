package testutils

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// TestSuite provides common test utilities and eliminates code duplication
type TestSuite struct {
	t *testing.T
}

// NewTestSuite creates a new test suite with common utilities
func NewTestSuite(t *testing.T) *TestSuite {
	return &TestSuite{t: t}
}

// HTTPTestSuite provides HTTP-specific test utilities
type HTTPTestSuite struct {
	*TestSuite
	Router   *gin.Engine
	Recorder *httptest.ResponseRecorder
}

// NewHTTPTestSuite creates a new HTTP test suite
func NewHTTPTestSuite(t *testing.T) *HTTPTestSuite {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	w := httptest.NewRecorder()

	return &HTTPTestSuite{
		TestSuite: NewTestSuite(t),
		Router:    router,
		Recorder:  w,
	}
}

// SetupRequest configures a new request for testing
func (hts *HTTPTestSuite) SetupRequest(method, url string) *http.Request {
	return httptest.NewRequest(method, url, nil)
}

// ExecuteRequest executes the configured request and returns the response
func (hts *HTTPTestSuite) ExecuteRequest(req *http.Request) *httptest.ResponseRecorder {
	hts.Router.ServeHTTP(hts.Recorder, req)
	return hts.Recorder
}

// AssertResponseStatus asserts the HTTP status code
func (hts *HTTPTestSuite) AssertResponseStatus(expected int) {
	assert.Equal(hts.t, expected, hts.Recorder.Code)
}

// AssertResponseContains asserts the response body contains expected text
func (hts *HTTPTestSuite) AssertResponseContains(expected string) {
	assert.Contains(hts.t, hts.Recorder.Body.String(), expected)
}

// AssertResponseHeader asserts a response header value
func (hts *HTTPTestSuite) AssertResponseHeader(key, expected string) {
	assert.Equal(hts.t, expected, hts.Recorder.Header().Get(key))
}

// LoggerTestSuite provides logger-specific test utilities
type LoggerTestSuite struct {
	*TestSuite
	Logger   Logger
	Observer *observer.ObservedLogs
}

// Logger interface for testing
type Logger interface {
	Debug(msg string, fields ...map[string]interface{})
	Info(msg string, fields ...map[string]interface{})
	Warn(msg string, fields ...map[string]interface{})
	Error(msg string, err error, fields ...map[string]interface{})
	Fatal(msg string, err error, fields ...map[string]interface{})
}

// NewLoggerTestSuite creates a new logger test suite
func NewLoggerTestSuite(t *testing.T, level zapcore.Level) *LoggerTestSuite {
	observedZapCore, observedLogs := observer.New(level)
	observedLogger := zap.New(observedZapCore)

	return &LoggerTestSuite{
		TestSuite: NewTestSuite(t),
		Logger:    &TestLogger{logger: observedLogger, level: level},
		Observer:  observedLogs,
	}
}

// TestLogger implements Logger interface for testing
type TestLogger struct {
	logger *zap.Logger
	level  zapcore.Level
}

func (tl *TestLogger) Debug(msg string, fields ...map[string]interface{}) {
	if tl.level <= zapcore.DebugLevel {
		tl.logger.Debug(msg, convertFields(fields...)...)
	}
}

func (tl *TestLogger) Info(msg string, fields ...map[string]interface{}) {
	if tl.level <= zapcore.InfoLevel {
		tl.logger.Info(msg, convertFields(fields...)...)
	}
}

func (tl *TestLogger) Warn(msg string, fields ...map[string]interface{}) {
	if tl.level <= zapcore.WarnLevel {
		tl.logger.Warn(msg, convertFields(fields...)...)
	}
}

func (tl *TestLogger) Error(msg string, err error, fields ...map[string]interface{}) {
	if tl.level <= zapcore.ErrorLevel {
		allFields := convertFields(fields...)
		if err != nil {
			allFields = append(allFields, zap.Error(err))
		}
		tl.logger.Error(msg, allFields...)
	}
}

func (tl *TestLogger) Fatal(msg string, err error, fields ...map[string]interface{}) {
	allFields := convertFields(fields...)
	if err != nil {
		allFields = append(allFields, zap.Error(err))
	}
	tl.logger.Fatal(msg, allFields...)
}

// WithRequestID adds request ID to logger
func (tl *TestLogger) WithRequestID(requestID string) *TestLogger {
	return &TestLogger{
		logger: tl.logger.With(zap.String("request_id", requestID)),
		level:  tl.level,
	}
}

// WithService adds service name to logger
func (tl *TestLogger) WithService(service string) *TestLogger {
	return &TestLogger{
		logger: tl.logger.With(zap.String("service", service)),
		level:  tl.level,
	}
}

// ConvertFields converts map fields to zap fields
func (tl *TestLogger) ConvertFields(fields ...map[string]interface{}) []zap.Field {
	return convertFields(fields...)
}

// GetLogger returns the underlying zap.Logger for testing purposes
func (tl *TestLogger) GetLogger() *zap.Logger {
	return tl.logger
}

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

// AssertLogLevel asserts the log level
func (lts *LoggerTestSuite) AssertLogLevel(expected zapcore.Level) {
	logs := lts.Observer.All()
	require.NotEmpty(lts.t, logs, "Expected logs but found none")
	assert.Equal(lts.t, expected, logs[0].Level)
}

// AssertLogMessage asserts the log message
func (lts *LoggerTestSuite) AssertLogMessage(expected string) {
	logs := lts.Observer.All()
	require.NotEmpty(lts.t, logs, "Expected logs but found none")
	assert.Equal(lts.t, expected, logs[0].Message)
}

// AssertLogContainsField asserts the log contains a specific field
func (lts *LoggerTestSuite) AssertLogContainsField(key string) {
	logs := lts.Observer.All()
	require.NotEmpty(lts.t, logs, "Expected logs but found none")

	fieldNames := make([]string, len(logs[0].Context))
	for i, field := range logs[0].Context {
		fieldNames[i] = field.Key
	}
	assert.Contains(lts.t, fieldNames, key)
}

// AssertLogFieldValue asserts a specific field value
func (lts *LoggerTestSuite) AssertLogFieldValue(key, expected string) {
	logs := lts.Observer.All()
	require.NotEmpty(lts.t, logs, "Expected logs but found none")

	for _, field := range logs[0].Context {
		if field.Key == key {
			assert.Equal(lts.t, expected, field.String)
			return
		}
	}
	lts.t.Errorf("Field %s not found in log context", key)
}

// ValidationTestSuite provides validation-specific test utilities
type ValidationTestSuite struct {
	*TestSuite
}

// NewValidationTestSuite creates a new validation test suite
func NewValidationTestSuite(t *testing.T) *ValidationTestSuite {
	return &ValidationTestSuite{TestSuite: NewTestSuite(t)}
}

// TestCase represents a generic test case
type TestCase struct {
	Name     string
	Input    interface{}
	Expected interface{}
	Setup    func() // Optional setup function
	Cleanup  func() // Optional cleanup function
}

// RunTestCases runs a series of test cases with common patterns
func (vts *ValidationTestSuite) RunTestCases(testCases []TestCase, testFunc func(tc TestCase)) {
	for _, tc := range testCases {
		vts.t.Run(tc.Name, func(t *testing.T) {
			if tc.Setup != nil {
				tc.Setup()
			}
			if tc.Cleanup != nil {
				defer tc.Cleanup()
			}
			testFunc(tc)
		})
	}
}

// ErrorTestSuite provides error-specific test utilities
type ErrorTestSuite struct {
	*TestSuite
}

// NewErrorTestSuite creates a new error test suite
func NewErrorTestSuite(t *testing.T) *ErrorTestSuite {
	return &ErrorTestSuite{TestSuite: NewTestSuite(t)}
}

// DatabaseTestSuite provides database-specific test utilities
type DatabaseTestSuite struct {
	*TestSuite
}

// NewDatabaseTestSuite creates a new database test suite
func NewDatabaseTestSuite(t *testing.T) *DatabaseTestSuite {
	return &DatabaseTestSuite{TestSuite: NewTestSuite(t)}
}

// SkipIfShort skips the test if running in short mode
func (ts *TestSuite) SkipIfShort() {
	if testing.Short() {
		ts.t.Skip("Skipping test in short mode")
	}
}

// Common assertion methods
func (ts *TestSuite) AssertNoError(err error) {
	require.NoError(ts.t, err)
}

func (ts *TestSuite) AssertError(err error) {
	assert.Error(ts.t, err)
}

func (ts *TestSuite) AssertEqual(expected, actual interface{}) {
	assert.Equal(ts.t, expected, actual)
}

func (ts *TestSuite) AssertNotNil(value interface{}) {
	assert.NotNil(ts.t, value)
}

func (ts *TestSuite) AssertTrue(condition bool) {
	assert.True(ts.t, condition)
}

func (ts *TestSuite) AssertFalse(condition bool) {
	assert.False(ts.t, condition)
}

func (ts *TestSuite) AssertContains(str, substr string) {
	assert.Contains(ts.t, str, substr)
}

func (ts *TestSuite) AssertNotEmpty(value interface{}) {
	assert.NotEmpty(ts.t, value)
}

func (ts *TestSuite) AssertEmpty(value interface{}) {
	assert.Empty(ts.t, value)
}

func (ts *TestSuite) AssertNil(value interface{}) {
	assert.Nil(ts.t, value)
}

func (ts *TestSuite) AssertNotEqual(expected, actual interface{}) {
	assert.NotEqual(ts.t, expected, actual)
}

// AssertLess asserts that the first value is less than the second
func (ts *TestSuite) AssertLess(actual, expected interface{}) {
	// Convert to float64 for comparison
	actualFloat, ok1 := actual.(float64)
	expectedFloat, ok2 := expected.(float64)

	if !ok1 || !ok2 {
		ts.t.Errorf("AssertLess requires float64 values, got %T and %T", actual, expected)
		return
	}

	if actualFloat >= expectedFloat {
		ts.t.Errorf("Expected %v to be less than %v", actual, expected)
	}
}

// AssertPanics asserts that the function panics
func (ts *TestSuite) AssertPanics(fn func()) {
	defer func() {
		if r := recover(); r == nil {
			ts.t.Errorf("Expected function to panic")
		}
	}()
	fn()
}

// AssertNotPanics asserts that the function does not panic
func (ts *TestSuite) AssertNotPanics(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			ts.t.Errorf("Expected function not to panic, but it panicked with: %v", r)
		}
	}()
	fn()
}

// AssertLen asserts that the slice/array has the expected length
func (ts *TestSuite) AssertLen(slice interface{}, expected int) {
	// Use reflection to get the length
	v := reflect.ValueOf(slice)
	if v.Kind() != reflect.Slice && v.Kind() != reflect.Array {
		ts.t.Errorf("AssertLen requires a slice or array, got %T", slice)
		return
	}

	actual := v.Len()
	if actual != expected {
		ts.t.Errorf("Expected length %d, got %d", expected, actual)
	}
}

// ContextTestSuite provides context-specific test utilities
type ContextTestSuite struct {
	*TestSuite
}

// NewContextTestSuite creates a new context test suite
func NewContextTestSuite(t *testing.T) *ContextTestSuite {
	return &ContextTestSuite{TestSuite: NewTestSuite(t)}
}

// CreateTestContext creates a test context with optional values
func (cts *ContextTestSuite) CreateTestContext(values map[string]interface{}) context.Context {
	ctx := context.Background()
	for key, value := range values {
		ctx = context.WithValue(ctx, key, value)
	}
	return ctx
}

// AssertContextValue asserts a context contains a specific value
func (cts *ContextTestSuite) AssertContextValue(ctx context.Context, key, expected interface{}) {
	actual := ctx.Value(key)
	assert.Equal(cts.t, expected, actual)
}
