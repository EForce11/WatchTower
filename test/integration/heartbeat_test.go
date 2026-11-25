package integration

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// heartbeatWait derives the observation window from WT_HEARTBEAT_INTERVAL:
// 1 immediate heartbeat + 7 ticks, plus slack. Defaults to 65s (10s interval).
func heartbeatWait() time.Duration {
	if v := os.Getenv("WT_HEARTBEAT_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d*7 + 2*time.Second
		}
	}
	return 65 * time.Second
}

// buildBinary compiles ./cmd/<name> into dir and returns the binary path.
// Building up front keeps compile time (slow on a cold CI cache) out of the
// heartbeat observation window, and lets the test kill the real process
// rather than a `go run` wrapper.
func buildBinary(t *testing.T, dir, name string) string {
	t.Helper()
	out := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", out, "../../cmd/"+name)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, b)
	}
	return out
}

// waitForPort polls addr until it accepts TCP connections or timeout elapses.
func waitForPort(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("Core did not start listening on %s within %v", addr, timeout)
}

// hasVersionAndTier reports whether a Core heartbeat log line carries the
// agent version and collector tier fields.
func hasVersionAndTier(line string) bool {
	return strings.Contains(line, "version=") && strings.Contains(line, "tier=")
}

// TestHeartbeatFlow tests end-to-end gRPC communication between
// wt-core (server) and wt-sentry (client).
//
// Run with:
//
//	go test -v -timeout 90s ./test/integration/
func TestHeartbeatFlow(t *testing.T) {
	// Child processes inherit this; must be set before the wait is computed.
	t.Setenv("WT_HEARTBEAT_INTERVAL", "1s")

	waitDuration := heartbeatWait()

	binDir := t.TempDir()
	coreBin := buildBinary(t, binDir, "wt-core")
	sentryBin := buildBinary(t, binDir, "wt-sentry")

	// Overall test budget: waitDuration + 10 s buffer for startup/shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), waitDuration+10*time.Second)
	defer cancel()

	// Thread-safe heartbeat counter.
	var mu sync.Mutex
	heartbeatCount := 0
	richCount := 0 // heartbeat lines carrying version= and tier=

	// -------------------------------------------------------------------------
	// 1. Start wt-core
	// -------------------------------------------------------------------------
	t.Log("Starting Core...")
	coreCmd := exec.CommandContext(ctx, coreBin)

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
				if hasVersionAndTier(line) {
					richCount++
				}
				count := heartbeatCount
				mu.Unlock()
				t.Logf("Heartbeat received (count: %d)", count)
			}
		}
	}()

	// Wait until Core accepts connections before starting Sentry.
	waitForPort(t, "127.0.0.1:50051", 10*time.Second)

	// -------------------------------------------------------------------------
	// 2. Start wt-sentry
	// -------------------------------------------------------------------------
	t.Log("Starting Sentry...")
	sentryCmd := exec.CommandContext(ctx, sentryBin)

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
	rich := richCount
	mu.Unlock()

	t.Logf("Final heartbeat count: %d", count)

	if count < 6 {
		t.Errorf("Expected at least 6 heartbeats, got %d", count)
	}
	if rich != count {
		t.Errorf("Expected every heartbeat log line to contain version= and tier=, got %d of %d", rich, count)
	}

	// Shutdown happens in the deferred Kill calls above.
	if !t.Failed() {
		t.Log("✅ Integration test passed")
	}
}
