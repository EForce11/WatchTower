.PHONY: proto proto-lint proto-check build test integration-test integration-test-race clean proto-clean run-core run-sentry run-interceptor dev-deps fmt lint cover cover-html check-coverage help all

# Make `go install`ed tools (protoc-gen-go, protoc-gen-go-grpc) visible
# even when $(go env GOPATH)/bin is not on the user's shell PATH.
export PATH := $(shell go env GOPATH)/bin:$(PATH)

# Default target
all: build

# Compile protobuf
proto:
	@echo "🔨 Generating protobuf..."
	buf generate
	@echo "✅ Protobuf generated"

# Lint protobuf definitions
proto-lint:
	buf lint

# Lint, regenerate, and fail if committed generated code is stale
proto-check:
	buf lint && buf generate && git diff --exit-code -- pkg/synapse

# Build all binaries
build: proto
	@echo "🔨 Building binaries..."
	@for dir in cmd/*/; do \
		name=$$(basename $$dir); \
		echo "go build -o $$name ./$$dir"; \
		go build -o $$name ./$$dir || exit 1; \
	done
	@echo "✅ Build complete"

# Run all tests
test:
	@echo "🧪 Running tests..."
	go test -v ./...
	@echo "✅ Tests passed"

# Run integration test only
integration-test:
	@echo "🧪 Running integration test..."
	go test -v ./test/integration/
	@echo "✅ Integration test passed"

# Run integration test with race detector
integration-test-race:
	@echo "🧪 Running integration test (race detector)..."
	go test -v -race ./test/integration/
	@echo "✅ Integration test passed (no races)"

# Clean build artifacts (preserves committed .pb.go files)
clean:
	@echo "🧹 Cleaning..."
	rm -f wt-core wt-sentry wt-cli wt-turret wt-interceptor
	@echo "✅ Clean complete"

# Clean everything including generated protobuf code (use before proto regeneration)
proto-clean:
	@echo "🧹 Cleaning protobuf generated code..."
	rm -f pkg/protocol/*.pb.go
	@echo "✅ Protobuf clean complete"

# Run Core server
run-core: build
	@echo "🚀 Starting WatchTower Core..."
	./wt-core

# Run Sentry agent
run-sentry: build
	@echo "🚀 Starting WatchTower Sentry..."
	./wt-sentry

# Run Interceptor agent (stub)
run-interceptor: build
	@echo "🚀 Starting WatchTower Interceptor..."
	./wt-interceptor

# Install development dependencies
dev-deps:
	@echo "📦 Installing development dependencies..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
	go install github.com/bufbuild/buf/cmd/buf@v1.50.0
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8
	@echo "✅ Dependencies installed"

# Format code
fmt:
	@echo "🎨 Formatting code..."
	go fmt ./...
	@echo "✅ Code formatted"

# Lint code
lint:
	@echo "🔍 Linting code..."
	golangci-lint run ./...
	@echo "✅ Lint complete"

# Run tests and generate coverage profile
# Excludes cmd/ (main packages) and generated .pb.go files — mirrors CI behaviour.
cover:
	@echo "📊 Generating coverage report..."
	go test -coverprofile=coverage.out -covermode=atomic ./internal/...
	go tool cover -func=coverage.out
	@echo "✅ Coverage report complete"

# Open coverage report in browser
cover-html: cover
	@echo "🌐 Opening coverage report in browser..."
	go tool cover -html=coverage.out

# Check coverage meets 75% threshold (mirrors CI — testable packages only)
check-coverage: cover
	@COVERAGE=$$(go tool cover -func=coverage.out | grep total | awk '{print $$3}' | tr -d '%'); \
	echo "Total coverage: $${COVERAGE}%"; \
	if awk "BEGIN {exit !($$COVERAGE < 75)}"; then \
		echo "❌ Coverage $${COVERAGE}% is below the 75% threshold"; exit 1; \
	fi; \
	echo "✅ Coverage $${COVERAGE}% meets the threshold"

# Show help
help:
	@echo "WatchTower XDR - Makefile Commands"
	@echo ""
	@echo "Build:"
	@echo "  make build              - Build all binaries"
	@echo "  make proto              - Generate protobuf (buf)"
	@echo "  make clean              - Remove build artifacts"
	@echo ""
	@echo "Run:"
	@echo "  make run-core           - Start Core server"
	@echo "  make run-sentry         - Start Sentry agent"
	@echo "  make run-interceptor    - Start Interceptor agent (stub)"
	@echo ""
	@echo "Test:"
	@echo "  make test               - Run all tests"
	@echo "  make integration-test   - Run integration test"
	@echo "  make cover              - Generate coverage report (terminal)"
	@echo "  make cover-html         - Open coverage report in browser"
	@echo "  make check-coverage     - Verify coverage meets 75%% threshold"
	@echo ""
	@echo "Development:"
	@echo "  make dev-deps           - Install dev dependencies"
	@echo "  make fmt                - Format code"
	@echo "  make lint               - Lint code"
