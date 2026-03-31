package sentry

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestMetricsCollector_SingleSnapshot verifies that Start() immediately
// delivers at least one SystemMetrics snapshot on the channel and that all
// percentage values are within [0, 100].
func TestMetricsCollector_SingleSnapshot(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mc := NewMetricsCollector(10 * time.Second) // long interval – we only want the first immediate collect
	mc.Start(ctx)

	select {
	case m, ok := <-mc.Metrics():
		if !ok {
			t.Fatal("metrics channel closed before delivering a snapshot")
		}

		t.Logf("Metrics: CPU=%.2f%%, Mem=%.2f%%, Disk=%.2f%%",
			m.CPUPercent, m.MemoryPercent, m.DiskPercent)

		if m.Timestamp <= 0 {
			t.Errorf("expected positive Timestamp, got %d", m.Timestamp)
		}
		assertPercent(t, "CPUPercent", m.CPUPercent)
		assertPercent(t, "MemoryPercent", m.MemoryPercent)
		assertPercent(t, "DiskPercent", m.DiskPercent)

	case <-ctx.Done():
		t.Fatal("timed out waiting for the first metrics snapshot")
	}
}

// TestMetricsCollector_MultipleSnapshots verifies that the collector keeps
// producing snapshots at the configured interval.
func TestMetricsCollector_MultipleSnapshots(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const wantCount = 3
	interval := 500 * time.Millisecond

	mc := NewMetricsCollector(interval)
	mc.Start(ctx)

	received := 0
	for received < wantCount {
		select {
		case m, ok := <-mc.Metrics():
			if !ok {
				t.Fatalf("channel closed after %d snapshots (want %d)", received, wantCount)
			}
			received++
			t.Logf("[%d] CPU=%.2f%% Mem=%.2f%% Disk=%.2f%%",
				received, m.CPUPercent, m.MemoryPercent, m.DiskPercent)
		case <-ctx.Done():
			t.Fatalf("timed out after %d snapshots (want %d)", received, wantCount)
		}
	}
}

// TestMetricsCollector_ContextCancellation verifies that the collector stops
// sending metrics after its context is cancelled.
func TestMetricsCollector_ContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())

	mc := NewMetricsCollector(200 * time.Millisecond)
	mc.Start(ctx)

	// Give it time to emit the first snapshot.
	time.Sleep(50 * time.Millisecond)

	// Cancel and drain whatever was buffered.
	cancel()
	time.Sleep(500 * time.Millisecond)

	// After cancellation no further snapshots should arrive within a reasonable
	// window.
	drainTimeout := time.NewTimer(600 * time.Millisecond)
	defer drainTimeout.Stop()

	// Drain any buffered items first.
drainLoop:
	for {
		select {
		case _, ok := <-mc.Metrics():
			if !ok {
				break drainLoop
			}
		default:
			break drainLoop
		}
	}

	// Now assert nothing new arrives.
	select {
	case _, ok := <-mc.Metrics():
		if ok {
			t.Fatal("received a metrics snapshot after context cancellation")
		}
	case <-drainTimeout.C:
		// Good – no new snapshots.
	}
}

// TestMetricsCollector_MemoryFields verifies that non-zero memory values are
// reported (assumes the tests run on a real OS with >0 MB RAM used).
func TestMetricsCollector_MemoryFields(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mc := NewMetricsCollector(10 * time.Second)
	mc.Start(ctx)

	m := <-mc.Metrics()

	if m.MemoryUsedMB == 0 {
		t.Error("MemoryUsedMB should be > 0 on a running system")
	}
}

// TestMetricsCollector_DiskFields verifies that non-zero disk values are
// reported (assumes / is mounted and has been used).
func TestMetricsCollector_DiskFields(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mc := NewMetricsCollector(10 * time.Second)
	mc.Start(ctx)

	m := <-mc.Metrics()

	if m.DiskUsedGB == 0 {
		t.Error("DiskUsedGB should be > 0 on a running system")
	}
}

// TestMetricsCollector_Close ensures that Close() shuts the channel cleanly
// and does not panic.
func TestMetricsCollector_Close(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mc := NewMetricsCollector(10 * time.Second)
	mc.Start(ctx)

	// Wait for the first snapshot to be in the buffer so the goroutine has
	// started, then cancel and close.
	time.Sleep(200 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	// Close must not panic.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Close() caused panic: %v", r)
		}
	}()
	mc.Close()

	// Close() seals the channel. Drain any snapshots that were buffered before
	// Close was called, then verify the channel is exhausted.
	ch := mc.Metrics()
	for {
		m, ok := <-ch
		if !ok {
			// Channel is closed and drained — this is the expected path.
			return
		}
		t.Logf("draining buffered snapshot ts=%d", m.Timestamp)
	}
}

// TestNewMetricsCollector verifies the constructor creates valid state.
func TestNewMetricsCollector(t *testing.T) {
	t.Parallel()

	const interval = 5 * time.Second
	mc := NewMetricsCollector(interval)

	if mc == nil {
		t.Fatal("NewMetricsCollector returned nil")
	}
	if mc.interval != interval {
		t.Errorf("interval: got %v, want %v", mc.interval, interval)
	}
	if mc.metrics == nil {
		t.Error("metrics channel should not be nil")
	}
	if cap(mc.metrics) != 10 {
		t.Errorf("channel capacity: got %d, want 10", cap(mc.metrics))
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// assertPercent fails t if v is outside [0, 100].
func assertPercent(t *testing.T, name string, v float64) {
	t.Helper()
	if v < 0 || v > 100 {
		t.Errorf("%s out of range: %.2f (want [0, 100])", name, v)
	}
	_ = fmt.Sprintf("%s=%.2f%%", name, v) // ensure formatted output compiles
}
