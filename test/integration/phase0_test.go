package integration

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestPhase0_HeartbeatFlow tests end-to-end gRPC communication between
// wt-core (server) and wt-sentry (client).
//
// Run with:
//
//	go test -v -timeout 90s ./test/integration/
func TestPhase0_HeartbeatFlow(t *testing.T) {
	// Overall test budget: 70 s (65 s observation + 5 s buffer for startup/shutdown).
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()

	// Thread-safe heartbeat counter.
	var mu sync.Mutex
	heartbeatCount := 0

	// -------------------------------------------------------------------------
	// 1. Start wt-core
	// -------------------------------------------------------------------------
	t.Log("Starting Core...")
	coreCmd := exec.CommandContext(ctx, "go", "run", "../../cmd/wt-core/main.go")

	// Go's log package writes to stderr, so heartbeat lines appear on stderr.
	coreStderr, err := coreCmd.StderrPipe()
	if err != nil {
		t.Fatalf("Failed to get Core stderr pipe: %v", err)
	}

	if err := coreCmd.Start(); err != nil {
		t.Fatalf("Failed to start Core: %v", err)
	}
	defer func() {
		if coreCmd.Process != nil {
			_ = coreCmd.Process.Kill()
		}
	}()

	t.Logf("Core PID: %d", coreCmd.Process.Pid)

	// Scan Core's stderr for heartbeat log lines in the background.
	go func() {
		scanner := bufio.NewScanner(coreStderr)
		for scanner.Scan() {
			line := scanner.Text()
			t.Log("[core]", line)
			if strings.Contains(line, "Heartbeat from") {
				mu.Lock()
				heartbeatCount++
				count := heartbeatCount
				mu.Unlock()
				t.Logf("Heartbeat received (count: %d)", count)
			}
		}
	}()

	// Give Core time to bind on :50051 before Sentry tries to connect.
	time.Sleep(2 * time.Second)

	// -------------------------------------------------------------------------
	// 2. Start wt-sentry
	// -------------------------------------------------------------------------
	t.Log("Starting Sentry...")
	sentryCmd := exec.CommandContext(ctx, "go", "run", "../../cmd/wt-sentry/main.go")

	// Capture Sentry stderr for visibility (optional but helpful for debugging).
	sentryStderr, err := sentryCmd.StderrPipe()
	if err != nil {
		t.Fatalf("Failed to get Sentry stderr pipe: %v", err)
	}

	if err := sentryCmd.Start(); err != nil {
		t.Fatalf("Failed to start Sentry: %v", err)
	}
	defer func() {
		if sentryCmd.Process != nil {
			_ = sentryCmd.Process.Kill()
		}
	}()

	t.Logf("Sentry PID: %d", sentryCmd.Process.Pid)

	go func() {
		scanner := bufio.NewScanner(sentryStderr)
		for scanner.Scan() {
			t.Log("[sentry]", scanner.Text())
		}
	}()

	// -------------------------------------------------------------------------
	// 3. Wait for heartbeats
	// -------------------------------------------------------------------------
	// Sentry sends 1 immediate heartbeat + 1 every 10 s.
	// In 65 s we expect: 1 + 6 = 7 heartbeats.  We assert ≥ 6 for a small margin.
	t.Log("Waiting 65 seconds for heartbeats...")
	time.Sleep(65 * time.Second)

	// -------------------------------------------------------------------------
	// 4. Verify heartbeat count
	// -------------------------------------------------------------------------
	mu.Lock()
	count := heartbeatCount
	mu.Unlock()

	t.Logf("Final heartbeat count: %d", count)

	if count < 6 {
		t.Errorf("Expected at least 6 heartbeats, got %d", count)
	}

	// -------------------------------------------------------------------------
	// 5. Clean shutdown
	// -------------------------------------------------------------------------
	t.Log("Shutting down components...")
	if sentryCmd.Process != nil {
		_ = sentryCmd.Process.Kill()
	}
	if coreCmd.Process != nil {
		_ = coreCmd.Process.Kill()
	}

	t.Log("✅ Integration test passed")
}
