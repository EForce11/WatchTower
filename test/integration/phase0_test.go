package integration

import (
	"bufio"
	"context"
	"os"
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
	// Calculate wait duration from configured heartbeat interval.
	// With 1s interval: 1 immediate + 7 ticks in 8 seconds = 8 heartbeats.
	// Default (10s interval): 1 immediate + 6 ticks in 65 seconds = 7 heartbeats.
	waitDuration := 65 * time.Second
	if v := os.Getenv("WT_HEARTBEAT_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			waitDuration = d*7 + 2*time.Second
		}
	}

	// Overall test budget: waitDuration + 10 s buffer for startup/shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), waitDuration+10*time.Second)
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
	sentryCmd.Env = append(os.Environ(), "WT_HEARTBEAT_INTERVAL=1s")

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
	// Sentry sends 1 immediate heartbeat + 1 per interval.
	// With 1s interval: 1 + 7 ticks in 8 s = 8 heartbeats. We assert ≥ 6 for variance.
	t.Logf("Waiting %v for heartbeats...", waitDuration)
	time.Sleep(waitDuration)

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
