# Changelog

All notable changes to WatchTower XDR are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

Phase 1 (Turret) of the v3.2 architecture.

### Added
- `wt-turret` root enforcement daemon (`serve`, `panic-flush`, `version`) with a single-instance lock on its state directory
- Safety layer: self-preservation ranges, minimum ban prefix, overlap refusal, origin rules, reflex budget and per-prefix limiter
- Signed commands (Ed25519 automation and admin keys) with a persisted replay cache
- Core-signed IOC bundle and `KILL_TEMP_MALWARE` re-verification of the process binary
- nftables firewall (`table inet watchtower`) with persisted bans that never shorten, and `panic-flush`
- Engine and Unix socket server with `SO_PEERCRED` peer checks
- Network-namespace tests (`make test-netns`), a CI `netns` job, and `test-netns` in `make verify` when user namespaces are available

### Changed
- `wt-turret` added to the GoReleaser builds
- Phase 1 defers `ISOLATE_HOST` / `RELEASE_HOST` and WebAuthn signatures

---

## [0.3.0] — 2026-11-25

Phase 0 (Contracts) of the v3.2 architecture.

### Added
- Phase 0 contracts: `synapse.v1` protobuf definitions under `proto/watchtower/synapse/v1/` with generated code in `pkg/synapse/v1/`, managed with `buf`
- `ValidateEvent` with event size limits
- Length-prefixed IPC framing for local Sentry/Turret messages
- SQL migrations (`deployments/sql`) and migrator in `internal/core/store`, with owner/runtime role split and TimescaleDB-backed tests
- Rule layout (`rules/`), WES field mapping and structural validation in `internal/rules`
- CI gates: lint, proto-check, static build, race-enabled tests, migration tests against TimescaleDB
- `make verify` to run the CI gate locally, and `make test-rules`
- `Migrate` fails with `ErrNoMigrations` on an empty migration set; `Bootstrap` and `Migrate` share an advisory lock

### Changed
- Go toolchain bumped to 1.25
- Heartbeat now carries agent version and collector tier (moved onto `synapse.v1`)
- Default Core address is `127.0.0.1:50051` (avoids `localhost` DNS stalls)
- Integration test builds the binaries first and waits for Core's port (reliable on cold CI caches)
- `REVOKE CREATE ON SCHEMA public FROM PUBLIC` in bootstrap (PostgreSQL 14 hardening)

### Removed
- `pkg/protocol` (replaced by `pkg/synapse/v1`)
- `cmd/wt-interceptor`
- `scripts/verify-phase0.sh` (replaced by `make verify`)
- `proto-clean` and `run-interceptor` Make targets
- Stray `opencode.json`

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

[Unreleased]: https://github.com/EForce11/WatchTower/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/EForce11/WatchTower/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/EForce11/WatchTower/compare/v0.2.0-alpha...v0.2.0
[0.2.0-alpha]: https://github.com/EForce11/WatchTower/compare/v0.1.0...v0.2.0-alpha
[0.1.0]: https://github.com/EForce11/WatchTower/releases/tag/v0.1.0
