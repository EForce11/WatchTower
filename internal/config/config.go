// Package config provides YAML-based configuration loading for WatchTower
// components. Each binary (wt-core, wt-sentry, …) has its own typed config
// struct. The Load functions read a YAML file from disk and unmarshal it into
// the corresponding struct.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------

// CoreConfig holds all wt-core runtime configuration.
type CoreConfig struct {
	Server ServerConfig `yaml:"server"`
	Log    LogConfig    `yaml:"log"`
}

// ServerConfig describes the gRPC listener.
type ServerConfig struct {
	// ListenAddress is the host:port (or :port) the gRPC server binds to.
	ListenAddress string `yaml:"listen_address"`
}

// ---------------------------------------------------------------------------
// Sentry
// ---------------------------------------------------------------------------

// SentryConfig holds all wt-sentry runtime configuration.
type SentryConfig struct {
	Agent     AgentConfig     `yaml:"agent"`
	Core      CoreConnection  `yaml:"core"`
	Heartbeat HeartbeatConfig `yaml:"heartbeat"`
	Log       LogConfig       `yaml:"log"`
}

// AgentConfig identifies the agent instance.
type AgentConfig struct {
	// ID is the unique identifier reported in heartbeats and logs.
	ID string `yaml:"id"`
}

// CoreConnection describes how Sentry connects to Core.
type CoreConnection struct {
	// Address is the host:port of the Core gRPC server.
	Address string `yaml:"address"`
	// MaxRetries is the number of connection attempts before giving up.
	MaxRetries int `yaml:"max_retries"`
}

// HeartbeatConfig controls heartbeat cadence and timeouts.
type HeartbeatConfig struct {
	// IntervalSeconds is the pause between successive heartbeat RPCs.
	IntervalSeconds int `yaml:"interval_seconds"`
	// TimeoutSeconds is the per-RPC deadline for a heartbeat call.
	TimeoutSeconds int `yaml:"timeout_seconds"`
}

// Interval returns the heartbeat interval as a time.Duration.
func (h HeartbeatConfig) Interval() time.Duration {
	return time.Duration(h.IntervalSeconds) * time.Second
}

// Timeout returns the heartbeat timeout as a time.Duration.
func (h HeartbeatConfig) Timeout() time.Duration {
	return time.Duration(h.TimeoutSeconds) * time.Second
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

// LogConfig holds logging-related settings shared across components.
type LogConfig struct {
	// Level controls the minimum log severity (e.g. "debug", "info", "warn").
	Level string `yaml:"level"`
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

// DefaultCoreConfig returns a CoreConfig populated with the built-in defaults
// that match the original hardcoded values.
func DefaultCoreConfig() CoreConfig {
	return CoreConfig{
		Server: ServerConfig{ListenAddress: ":50051"},
		Log:    LogConfig{Level: "info"},
	}
}

// DefaultSentryConfig returns a SentryConfig populated with the built-in
// defaults that match the original hardcoded values.
func DefaultSentryConfig() SentryConfig {
	return SentryConfig{
		Agent:     AgentConfig{ID: "sentry-001"},
		Core:      CoreConnection{Address: "localhost:50051", MaxRetries: 3},
		Heartbeat: HeartbeatConfig{IntervalSeconds: 10, TimeoutSeconds: 5},
		Log:       LogConfig{Level: "info"},
	}
}

// ---------------------------------------------------------------------------
// Loaders
// ---------------------------------------------------------------------------

// LoadCoreConfig reads a YAML file at path and returns a CoreConfig.
// Returns an error if the file cannot be read or contains invalid YAML.
func LoadCoreConfig(path string) (CoreConfig, error) {
	var cfg CoreConfig
	if err := loadYAML(path, &cfg); err != nil {
		return CoreConfig{}, fmt.Errorf("loading core config: %w", err)
	}
	return cfg, nil
}

// LoadSentryConfig reads a YAML file at path and returns a SentryConfig.
// Returns an error if the file cannot be read or contains invalid YAML.
func LoadSentryConfig(path string) (SentryConfig, error) {
	var cfg SentryConfig
	if err := loadYAML(path, &cfg); err != nil {
		return SentryConfig{}, fmt.Errorf("loading sentry config: %w", err)
	}
	return cfg, nil
}

// loadYAML is a small helper that reads a file and unmarshals it.
func loadYAML(path string, dest interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	return nil
}
