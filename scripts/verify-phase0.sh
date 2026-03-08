#!/bin/bash
# WatchTower Phase 0 Verification Script
# Checks if Phase 0 is complete and working

set -e  # Exit on any error

echo "🔍 WatchTower Phase 0 Verification"
echo "===================================="
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check function
check() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ $1${NC}"
    else
        echo -e "${RED}❌ $1${NC}"
        exit 1
    fi
}

# 1. Check files exist
echo "📁 Checking file structure..."
test -f cmd/wt-core/main.go
check "Core server exists"

test -f cmd/wt-sentry/main.go
check "Sentry client exists"

test -f pkg/protocol/agent.proto
check "Protocol definition exists"

test -f test/integration/phase0_test.go
check "Integration test exists"

test -f go.mod
check "Go module initialized"

echo ""

# 2. Check protobuf compilation
echo "🔨 Checking protobuf compilation..."
protoc --go_out=. --go-grpc_out=. pkg/protocol/agent.proto 2>/dev/null
check "Protobuf compiles"

test -f pkg/protocol/agent.pb.go
check "Protobuf Go code exists"

echo ""

# 3. Check Go builds
echo "🔨 Checking Go builds..."
go build -o /tmp/wt-core cmd/wt-core/main.go
check "Core builds successfully"

go build -o /tmp/wt-sentry cmd/wt-sentry/main.go
check "Sentry builds successfully"

rm -f /tmp/wt-core /tmp/wt-sentry

echo ""

# 4. Check tests
echo "🧪 Running tests..."
go test ./test/integration/ -timeout 70s > /dev/null 2>&1
check "Integration test passes"

echo ""

# 5. Summary
echo "===================================="
echo -e "${GREEN}🎉 Phase 0 Verification Complete!${NC}"
echo ""
echo "Phase 0 Status: ✅ COMPLETE"
echo "Next: Phase 1 (Log Monitoring)"
echo ""
echo "To run:"
echo "  make run-core    # Terminal 1"
echo "  make run-sentry  # Terminal 2"
echo ""
