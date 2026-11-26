.PHONY: verify proto proto-lint proto-check build test integration-test integration-test-race clean run-core run-sentry dev-deps test-rules test-netns fmt lint cover cover-html check-coverage help all

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
	buf lint && buf generate && git diff --exit-code -- pkg/synapse && test -z "$$(git status --porcelain -- pkg/synapse)"

# Run the full CI gate locally: proto-check, static build, lint, tests
verify: proto-check
	@echo "Verifying (CGO_ENABLED=0 build, lint, test)..."
	CGO_ENABLED=0 go build ./...
	$(MAKE) lint
	@test -n "$$WT_TEST_DATABASE_URL" || echo "⚠️  WT_TEST_DATABASE_URL not set: migration tests skipped"
	go test -race ./internal/... ./pkg/...
	go test ./test/integration/ ./cmd/wt-turret/
	@if unshare --user --map-root-user --net true 2>/dev/null; then \
		$(MAKE) test-netns; \
	else \
		echo "⚠️  unprivileged user namespaces unavailable: test-netns skipped (CI runs the netns job)"; \
	fi
	@echo "Verify complete"

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

# Run rule-pack tests
test-rules:
	go test ./internal/rules/

# Run nftables netns tests (unprivileged: user + network namespace). -p 1:
# both packages share the namespace and the one watchtower table (the smoke
# test's panic-flush deletes it), so they must not run concurrently.
test-netns:
	unshare --user --map-root-user --net env GOPROXY=off GOFLAGS=-mod=readonly go test -p 1 -tags netns -race ./internal/turret/nft/ ./cmd/wt-turret/

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
	rm -f wt-core wt-sentry wt-cli wt-turret
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
	@echo "  make verify             - Run the CI gate locally (proto-check, build, lint, race tests; DB tests need WT_TEST_DATABASE_URL)"
	@echo "  make clean              - Remove build artifacts"
	@echo ""
	@echo "Run:"
	@echo "  make run-core           - Start Core server"
	@echo "  make run-sentry         - Start Sentry agent"
	@echo ""
	@echo "Test:"
	@echo "  make test               - Run all tests"
	@echo "  make test-rules         - Run rule-pack tests"
	@echo "  make test-netns         - Run nftables tests in a network namespace"
	@echo "  make integration-test   - Run integration test"
	@echo "  make cover              - Generate coverage report (terminal)"
	@echo "  make cover-html         - Open coverage report in browser"
	@echo "  make check-coverage     - Verify coverage meets 75%% threshold"
	@echo ""
	@echo "Development:"
	@echo "  make dev-deps           - Install dev dependencies"
	@echo "  make fmt                - Format code"
	@echo "  make lint               - Lint code"
