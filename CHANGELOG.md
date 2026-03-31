# Changelog

All notable changes to WatchTower XDR are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### In Progress
- Phase 1: Real-time log monitoring via fsnotify
- Phase 1: Security event pattern matching (regex-based rules)
- Phase 1: Log event streaming from sentry to core

---

## [0.2.0] — 2025-03-19

### Added
- `internal/sentry`: `LogWatcher` — real-time log monitoring using `fsnotify` (inotify)
- `internal/sentry`: `PatternMatcher` — regex-based security event detection engine
- `cmd/wt-cli`: placeholder binary for future CLI management tool
- CI pipeline with GitHub Actions: unit tests, linting (`golangci-lint`), race detector
- CodeQL security analysis workflow (scheduled weekly + on push/PR)
- Branch protection infrastructure: `CODEOWNERS`, Dependabot, PR title checker, PR template
- GoReleaser configuration for automated binary releases
- Release workflow triggered on semver tags (`v*`)

### Changed
- `cmd/wt-sentry`: replaced deprecated `grpc.Dial` with `grpc.NewClient`
- `cmd/wt-sentry`: replaced deprecated `os.SEEK_SET`/`os.SEEK_CUR` with `io.SeekStart`/`io.SeekCurrent`
- `go.mod`: removed legacy `github.com/golang/protobuf` wrapper dependency
- Integration test: heartbeat interval configurable via `HEARTBEAT_INTERVAL_MS` env variable for faster CI runs

### Fixed
- `LogWatcher.Close()`: added `sync.Once` to prevent double-close panic

---

## [0.2.0-alpha] — 2025-03-09

### Added
- `pkg/protocol`: gRPC protocol definition (`agent.proto`) with `HeartbeatRequest` / `HeartbeatResponse`
- `pkg/protocol`: compiled Go bindings (`agent.pb.go`, `agent_grpc.pb.go`)
- `cmd/wt-core`: central gRPC server, listens on `:50051`, handles `Heartbeat` RPC
- `cmd/wt-sentry`: monitoring agent, connects to core, sends heartbeat every 10s with exponential backoff reconnect
- Graceful shutdown on `SIGINT` / `SIGTERM` in both binaries
- `test/integration`: Phase 0 end-to-end integration test (core ↔ sentry heartbeat)
- `scripts/verify-phase0.sh`: automated Phase 0 completion check
- `Makefile`: `build`, `test`, `integration-test`, `lint`, `fmt`, `proto`, `dev-deps`, `help`
- `LICENSE`: GNU General Public License v3.0

---

## [0.1.0] — 2025-03-09

### Added
- Initial project scaffold (`go.mod`, directory structure)
- `.gitignore`, `.golangci.yml`, `.goreleaser.yml` baseline configuration

---

[Unreleased]: https://github.com/EForce11/WatchTower/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/EForce11/WatchTower/compare/v0.2.0-alpha...v0.2.0
[0.2.0-alpha]: https://github.com/EForce11/WatchTower/compare/v0.1.0...v0.2.0-alpha
[0.1.0]: https://github.com/EForce11/WatchTower/releases/tag/v0.1.0
