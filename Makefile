.PHONY: proto build test integration-test integration-test-race clean proto-clean run-core run-sentry run-turret run-interceptor dev-deps fmt lint cover cover-html check-coverage help all

# Default target
all: build

# Compile protobuf
proto:
	@echo "🔨 Compiling protobuf..."
	protoc --go_out=. --go_opt=module=github.com/EForce11/WatchTower \
	       --go-grpc_out=. --go-grpc_opt=module=github.com/EForce11/WatchTower \
	       pkg/protocol/agent.proto
	@echo "✅ Protobuf compiled"

# Build all binaries
build: proto
	@echo "🔨 Building binaries..."
	go build -o wt-core cmd/wt-core/main.go
	go build -o wt-sentry cmd/wt-sentry/main.go
	go build -o wt-turret cmd/wt-turret/main.go
	go build -o wt-interceptor cmd/wt-interceptor/main.go
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

# Run Turret agent (stub)
run-turret: build
	@echo "🚀 Starting WatchTower Turret..."
	./wt-turret

# Run Interceptor agent (stub)
run-interceptor: build
	@echo "🚀 Starting WatchTower Interceptor..."
	./wt-interceptor

# Install development dependencies
dev-deps:
	@echo "📦 Installing development dependencies..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
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
	@echo "  make proto              - Compile protobuf"
	@echo "  make clean              - Remove build artifacts"
	@echo ""
	@echo "Run:"
	@echo "  make run-core           - Start Core server"
	@echo "  make run-sentry         - Start Sentry agent"
	@echo "  make run-turret         - Start Turret agent (stub)"
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
