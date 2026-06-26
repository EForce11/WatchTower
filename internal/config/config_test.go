package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Core config tests
// ---------------------------------------------------------------------------

func TestLoadCoreConfig_Valid(t *testing.T) {
	content := `
server:
  listen_address: ":9090"
log:
  level: "debug"
`
	path := writeTempYAML(t, "core-*.yaml", content)

	cfg, err := LoadCoreConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.ListenAddress != ":9090" {
		t.Errorf("ListenAddress = %q, want %q", cfg.Server.ListenAddress, ":9090")
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, "debug")
	}
}

func TestLoadCoreConfig_FileNotFound(t *testing.T) {
	_, err := LoadCoreConfig("/nonexistent/core.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadCoreConfig_MalformedYAML(t *testing.T) {
	content := `server: [invalid`
	path := writeTempYAML(t, "core-bad-*.yaml", content)

	_, err := LoadCoreConfig(path)
	if err == nil {
		t.Fatal("expected error for malformed YAML, got nil")
	}
}

// ---------------------------------------------------------------------------
// Sentry config tests
// ---------------------------------------------------------------------------

func TestLoadSentryConfig_Valid(t *testing.T) {
	content := `
agent:
  id: "test-sentry-42"
core:
  address: "10.0.0.1:50051"
  max_retries: 5
heartbeat:
  interval_seconds: 30
  timeout_seconds: 10
log:
  level: "warn"
`
	path := writeTempYAML(t, "sentry-*.yaml", content)

	cfg, err := LoadSentryConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Agent.ID != "test-sentry-42" {
		t.Errorf("Agent.ID = %q, want %q", cfg.Agent.ID, "test-sentry-42")
	}
	if cfg.Core.Address != "10.0.0.1:50051" {
		t.Errorf("Core.Address = %q, want %q", cfg.Core.Address, "10.0.0.1:50051")
	}
	if cfg.Core.MaxRetries != 5 {
		t.Errorf("Core.MaxRetries = %d, want %d", cfg.Core.MaxRetries, 5)
	}
	if cfg.Heartbeat.IntervalSeconds != 30 {
		t.Errorf("Heartbeat.IntervalSeconds = %d, want %d", cfg.Heartbeat.IntervalSeconds, 30)
	}
	if cfg.Heartbeat.TimeoutSeconds != 10 {
		t.Errorf("Heartbeat.TimeoutSeconds = %d, want %d", cfg.Heartbeat.TimeoutSeconds, 10)
	}
	if cfg.Log.Level != "warn" {
		t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, "warn")
	}
}

func TestLoadSentryConfig_FileNotFound(t *testing.T) {
	_, err := LoadSentryConfig("/nonexistent/sentry.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadSentryConfig_MalformedYAML(t *testing.T) {
	content := `agent: [bad`
	path := writeTempYAML(t, "sentry-bad-*.yaml", content)

	_, err := LoadSentryConfig(path)
	if err == nil {
		t.Fatal("expected error for malformed YAML, got nil")
	}
}

// ---------------------------------------------------------------------------
// Default config tests
// ---------------------------------------------------------------------------

func TestDefaultCoreConfig(t *testing.T) {
	cfg := DefaultCoreConfig()
	if cfg.Server.ListenAddress != ":50051" {
		t.Errorf("default ListenAddress = %q, want %q", cfg.Server.ListenAddress, ":50051")
	}
}

func TestDefaultSentryConfig(t *testing.T) {
	cfg := DefaultSentryConfig()
	if cfg.Agent.ID != "sentry-001" {
		t.Errorf("default Agent.ID = %q, want %q", cfg.Agent.ID, "sentry-001")
	}
	if cfg.Core.Address != "localhost:50051" {
		t.Errorf("default Core.Address = %q, want %q", cfg.Core.Address, "localhost:50051")
	}
	if cfg.Heartbeat.IntervalSeconds != 10 {
		t.Errorf("default IntervalSeconds = %d, want %d", cfg.Heartbeat.IntervalSeconds, 10)
	}
	if cfg.Heartbeat.TimeoutSeconds != 5 {
		t.Errorf("default TimeoutSeconds = %d, want %d", cfg.Heartbeat.TimeoutSeconds, 5)
	}
}

// ---------------------------------------------------------------------------
// Duration helper tests
// ---------------------------------------------------------------------------

func TestHeartbeatConfig_Interval(t *testing.T) {
	h := HeartbeatConfig{IntervalSeconds: 15}
	if got := h.Interval(); got != 15*time.Second {
		t.Errorf("Interval() = %v, want %v", got, 15*time.Second)
	}
}

func TestHeartbeatConfig_Timeout(t *testing.T) {
	h := HeartbeatConfig{TimeoutSeconds: 3}
	if got := h.Timeout(); got != 3*time.Second {
		t.Errorf("Timeout() = %v, want %v", got, 3*time.Second)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// writeTempYAML creates a temporary YAML file and returns its path.
// The file is automatically removed when the test completes.
func writeTempYAML(t *testing.T, pattern, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, pattern)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp YAML: %v", err)
	}
	return path
}
