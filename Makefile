# Go Common Library Makefile
.PHONY: test test-verbose test-coverage test-race clean tidy lint

# Test commands
test:
	go test ./...

test-verbose:
	go test -v ./...

test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

test-race:
	go test -race ./...

test-all: test-race test-coverage
	@echo "All tests completed"

# Development commands
clean:
	rm -f coverage.out coverage.html
	go clean -testcache

tidy:
	go mod tidy

lint:
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run

# CI command
ci: tidy lint test-all
	@echo "CI pipeline completed successfully"

# Help
help:
	@echo "Available targets:"
	@echo "  test         - Run all tests"
	@echo "  test-verbose - Run tests with verbose output"
	@echo "  test-coverage- Run tests with coverage report"
	@echo "  test-race    - Run tests with race detection"
	@echo "  test-all     - Run all test variations"
	@echo "  clean        - Clean test cache and coverage files"
	@echo "  tidy         - Tidy go modules"
	@echo "  lint         - Run linter"
	@echo "  ci           - Run CI pipeline (tidy, lint, test-all)"
	@echo "  help         - Show this help message"
