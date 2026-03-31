// Package main is the entry point for the wt-cli command-line tool.
// wt-cli will provide a unified interface for interacting with the
// WatchTower XDR platform (query logs, manage agents, view alerts).
//
// TODO: Implement CLI commands (Phase 3+)
package main

// Version metadata injected at build time via ldflags.
// Example: -X main.Version=v1.0.0 -X main.Commit=abc1234 -X main.BuildDate=2025-01-01
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

func main() {
	// Placeholder — CLI implementation is scheduled for a future phase.
	// See docs/architecture.md and progress.md for the roadmap.
}
