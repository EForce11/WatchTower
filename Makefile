.PHONY: proto build test integration-test integration-test-race clean run-core run-sentry dev-deps fmt lint help all

# Default target
all: build

# Compile protobuf
proto:
	@echo "🔨 Compiling protobuf..."
	protoc --go_out=. --go-grpc_out=. pkg/protocol/agent.proto
	@echo "✅ Protobuf compiled"

# Build all binaries
build: proto
	@echo "🔨 Building binaries..."
	go build -o wt-core cmd/wt-core/main.go
	go build -o wt-sentry cmd/wt-sentry/main.go
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

# Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	rm -f wt-core wt-sentry wt-cli
	rm -f pkg/protocol/*.pb.go
	@echo "✅ Clean complete"

# Run Core server
run-core: build
	@echo "🚀 Starting WatchTower Core..."
	./wt-core

# Run Sentry agent
run-sentry: build
	@echo "🚀 Starting WatchTower Sentry..."
	./wt-sentry

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
	golint ./...
	@echo "✅ Lint complete"

# Show help
help:
	@echo "WatchTower XDR - Makefile Commands"
	@echo ""
	@echo "Build:"
	@echo "  make build           - Build all binaries"
	@echo "  make proto           - Compile protobuf"
	@echo "  make clean           - Remove build artifacts"
	@echo ""
	@echo "Run:"
	@echo "  make run-core        - Start Core server"
	@echo "  make run-sentry      - Start Sentry agent"
	@echo ""
	@echo "Test:"
	@echo "  make test            - Run all tests"
	@echo "  make integration-test - Run integration test"
	@echo ""
	@echo "Development:"
	@echo "  make dev-deps        - Install dev dependencies"
	@echo "  make fmt             - Format code"
	@echo "  make lint            - Lint code"
