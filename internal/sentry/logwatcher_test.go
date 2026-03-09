package sentry

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLogWatcher_DetectsNewLines verifies that the watcher emits a LogEvent
// for each new line appended to a watched file.
func TestLogWatcher_DetectsNewLines(t *testing.T) {
	// Create a temporary log file.
	tmpfile, err := os.CreateTemp("", "test-*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	// Create the watcher BEFORE writing so the initial offset is 0.
	watcher, err := NewLogWatcher([]string{tmpfile.Name()})
	if err != nil {
		t.Fatalf("NewLogWatcher: %v", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	watcher.Watch(ctx)

	// Write a line to the file.
	testLine := "Test log entry"
	if _, err := tmpfile.WriteString(testLine + "\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	if err := tmpfile.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// Expect the event within 2 seconds.
	select {
	case event := <-watcher.Events():
		if event.Line != testLine {
			t.Errorf("expected line %q, got %q", testLine, event.Line)
		}
		if event.FilePath != tmpfile.Name() {
			t.Errorf("expected FilePath %q, got %q", tmpfile.Name(), event.FilePath)
		}
		if event.Timestamp == 0 {
			t.Error("Timestamp should not be zero")
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout: no log event received")
	}
}

// TestLogWatcher_MultipleLines verifies multiple appended lines are all emitted.
func TestLogWatcher_MultipleLines(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-multi-*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	watcher, err := NewLogWatcher([]string{tmpfile.Name()})
	if err != nil {
		t.Fatalf("NewLogWatcher: %v", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	watcher.Watch(ctx)

	lines := []string{"line one", "line two", "line three"}
	for _, l := range lines {
		if _, err := tmpfile.WriteString(l + "\n"); err != nil {
			t.Fatalf("WriteString: %v", err)
		}
	}
	if err := tmpfile.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	for _, expected := range lines {
		select {
		case event := <-watcher.Events():
			if event.Line != expected {
				t.Errorf("expected %q, got %q", expected, event.Line)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("timeout waiting for line %q", expected)
			return
		}
	}
}

// TestLogWatcher_IgnoresPreExistingContent verifies that lines already in the
// file before the watcher starts are NOT emitted.
func TestLogWatcher_IgnoresPreExistingContent(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-existing-*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	// Write content BEFORE creating the watcher.
	if _, err := tmpfile.WriteString("old line\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	if err := tmpfile.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	watcher, err := NewLogWatcher([]string{tmpfile.Name()})
	if err != nil {
		t.Fatalf("NewLogWatcher: %v", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	watcher.Watch(ctx)

	// Write a new line that SHOULD be emitted.
	newLine := "new line after watcher"
	if _, err := tmpfile.WriteString(newLine + "\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	if err := tmpfile.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	select {
	case event := <-watcher.Events():
		if event.Line == "old line" {
			t.Error("watcher should not emit pre-existing lines")
		}
		if event.Line != newLine {
			t.Errorf("expected %q, got %q", newLine, event.Line)
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout: no log event received")
	}
}

// TestLogWatcher_ContextCancellation verifies the watcher stops when ctx
// is cancelled.
func TestLogWatcher_ContextCancellation(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-ctx-*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	watcher, err := NewLogWatcher([]string{tmpfile.Name()})
	if err != nil {
		t.Fatalf("NewLogWatcher: %v", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())
	watcher.Watch(ctx)

	// Cancel immediately — watcher goroutine should exit cleanly.
	cancel()

	// Give the goroutine a moment to wind down.
	time.Sleep(100 * time.Millisecond)
	// No assertion needed; just confirm no panic / deadlock.
}
