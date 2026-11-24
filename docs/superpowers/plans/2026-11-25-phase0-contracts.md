# Phase 0 — Contracts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lock the v3.2 contracts (protobuf, SQL schema, rule layout) and the CI gates that keep them honest, and move the existing `v0.2.0` prototype onto them. Target: `v0.3.0`.

**Architecture:** Protobuf sources live in `proto/watchtower/synapse/v1/` and are generated with `buf` into `pkg/synapse/v1` (package `synapsev1`). The generated code is committed, and CI fails if regeneration changes it. SQL migrations are plain numbered files embedded into a small pgx-based migrator. Superuser-only setup (roles, extension) is split from owner-run migrations. Rules are Sigma YAML files under `rules/`, checked structurally by a Go test. The existing heartbeat flow keeps working on the new contracts.

**Tech Stack:** Go 1.24 (`CGO_ENABLED=0`), buf v1.50.0 with `protoc-gen-go` / `protoc-gen-go-grpc`, `github.com/jackc/pgx/v5`, TimescaleDB `timescale/timescaledb:2.17.2-pg16` (CI service), golangci-lint v1.64.8, `gopkg.in/yaml.v3` (already a dependency).

**Spec:** `docs/architecture.md` (v3.2): §2.2, §3.1.6, §3.4.1, §4.1, §4.2, §4.3, §5.2, §7 Phase 0, §8.

## Global Constraints

- Every binary builds with `CGO_ENABLED=0 go build ./...`.
- No Redis or message brokers. PostgreSQL 14+ with TimescaleDB is the only data store.
- Protobuf package: `watchtower.synapse.v1`. `go_package = "github.com/EForce11/WatchTower/pkg/synapse/v1;synapsev1"`.
- `buf lint` uses the `STANDARD` rule set with no exceptions, which means `*_UNSPECIFIED = 0` enum zero values and enum values prefixed with the enum name.
- Generated `.pb.go` files are committed. `make proto-check` must leave `git diff --exit-code` clean.
- Database objects are owned by role `wt_owner`. The runtime role `wt_core` never gets `UPDATE`, `DELETE` or `TRUNCATE` on `audit_logs`.
- Event limits from §4.1: `attrs` ≤ 16 keys and ≤ 256 bytes per value; `raw_excerpt` ≤ 512 bytes.
- Reflex IPC frame: 4-byte big-endian length prefix, max payload 65536 bytes.
- The `.golangci.yml` stays in v1 format (pinned v1.64.8). Migrating to v2 is out of scope.

## Review Focus

1. **Wrong role when migrating:** running `Migrate` as a role that can't `SET ROLE wt_owner` should fail with a clear error, not silently create tables owned by the wrong role. Task 4 tests this.
2. **Partial migration:** a file that fails halfway should leave no trace (each file runs in its own transaction) and should not be recorded in `schema_migrations`. Task 4 tests this.
3. **Oversized or truncated IPC frames:** a peer sending a length > 65536 or closing mid-frame must give an error, never a huge allocation or a hang. Task 3 tests this.
4. **Generated code drift:** someone edits a `.proto` file without regenerating, and CI must catch it. Task 7 wires this into CI (`proto-check`).
5. **Rule IDs colliding or malformed:** two rule files with the same `id`, or an `id` that isn't a UUID, must fail the rules test. Task 5 tests this.

---

## File Structure

```
proto/watchtower/synapse/v1/
  event.proto        # WES Event, entities, EventBatch
  command.proto      # Action, CommandPayload, SignedCommand
  agent.proto        # AgentService: Heartbeat, EnrollAgent, StreamEvents, CommandStream, ReportCommandResult
  ipc.proto          # Sentry↔Turret: ReflexRequest, TurretRequest, TurretResponse
buf.yaml             # module root: proto/
buf.gen.yaml         # protoc-gen-go + protoc-gen-go-grpc, out=., module=github.com/EForce11/WatchTower
pkg/synapse/v1/      # generated (*.pb.go, *_grpc.pb.go) + hand-written:
  validate.go        # ValidateEvent
  validate_test.go
  frame.go           # WriteFrame / ReadFrame
  frame_test.go
deployments/sql/
  embed.go           # package sqlmigrations; var FS embed.FS
  bootstrap.sql      # superuser: extension, roles, schema privileges
  migrations/0001_fleet.sql … 0006_grants.sql
internal/core/store/
  migrate.go         # Bootstrap, Migrate
  migrate_test.go    # needs WT_TEST_DATABASE_URL, skips otherwise
rules/
  README.md
  wes-mapping.yaml
  agent/linux/sshd/ssh_auth_failure.yml (+ .samples.yml)
  agent/linux/sshd/ssh_brute_force.yml  (+ .samples.yml)
internal/rules/
  spec.go            # LoadDir, Rule
  spec_test.go       # validates the real rules/ tree
```

Deleted: `pkg/protocol/`, `cmd/wt-interceptor/`, `scripts/verify-phase0.sh`.
Renamed: `test/integration/phase0_test.go` → `test/integration/heartbeat_test.go`.

---

### Task 1: Protobuf toolchain and contracts

**Files:**
- Create: `buf.yaml`, `buf.gen.yaml`, `proto/watchtower/synapse/v1/{event,command,agent,ipc}.proto`
- Generate: `pkg/synapse/v1/*.pb.go`
- Modify: `Makefile` (`proto`, `proto-lint`, `proto-check`, `dev-deps`)

**Interfaces:**
- Produces (Go, package `synapsev1`):
  - `Event`, `EventBatch`, `Endpoint`, `User`, `Process`, `File`, `Http`, `Auth`; enums `EventClass`, `Severity`, `AuthOutcome`, `PackageStatus`
  - `Action` (enum), `SignatureScheme` (enum), `CommandPayload`, `SignedCommand`, `WebAuthnAssertion`
  - `AgentServiceServer` / `AgentServiceClient` with `Heartbeat`, `EnrollAgent`, `StreamEvents`, `CommandStream`, `ReportCommandResult`
  - `HeartbeatRequest`, `HeartbeatResponse`, `AgentStatus`, `CollectorTier`
  - `ReflexRequest`, `TurretRequest` (oneof `reflex` | `signed`), `TurretResponse`, `TurretResult`

Field numbers and names are copied from spec §4.1 (Event) and §5.2 (CommandPayload). Additions to the spec are listed per message below.

- [ ] **Step 1: Write `buf.yaml` / `buf.gen.yaml`**

`buf.yaml`: `version: v2`, `modules: [{path: proto}]`, `lint.use: [STANDARD]`, `breaking.use: [FILE]`.
`buf.gen.yaml`: `version: v2`, plugins `local: protoc-gen-go` and `local: protoc-gen-go-grpc`, both `out: .` and `opt: module=github.com/EForce11/WatchTower`.

- [ ] **Step 2: Write `event.proto`**

- `EventClass`: `EVENT_CLASS_UNSPECIFIED`, `_AUTHENTICATION`, `_HTTP_ACTIVITY`, `_PROCESS_ACTIVITY`, `_NETWORK_ACTIVITY`, `_FILE_ACTIVITY`, `_METRIC_SAMPLE`, `_DETECTION_FINDING`.
- `Severity`: `_UNSPECIFIED`, `_INFO`, `_LOW`, `_MEDIUM`, `_HIGH`, `_CRITICAL`.
- `Event` fields 1–14 exactly as in §4.1 (`time` is `google.protobuf.Timestamp`).
- `Process`: `pid`, `ppid`, `exe`, `cmdline`, `uid`, `start_time` (int64, `/proc/<pid>/stat` field 22), `parent_exe`.
- `File`: `path`, `sha256` (bytes), `owner`, `mode` (uint32), `package_status` (enum `PACKAGE_STATUS_UNSPECIFIED`, `_CONSISTENT`, `_MODIFIED`, `_UNOWNED`).
- `Auth`: `outcome` (enum `AUTH_OUTCOME_UNSPECIFIED`, `_SUCCESS`, `_FAILURE`), `method`, `service`.
- `EventBatch`: `agent_id`, `uint64 batch_seq`, `repeated Event events`.

- [ ] **Step 3: Write `command.proto`**

- `Action`: `ACTION_UNSPECIFIED`, `_RATE_LIMIT`, `_BAN_TEMP`, `_UNBAN`, `_KILL_TEMP_MALWARE`, `_BAN_PERM`, `_KILL_PROCESS`, `_ISOLATE_HOST`, `_RELEASE_HOST`.
- `CommandPayload` fields 1–9 as in §5.2.
- `SignedCommand`: `bytes payload = 1; bytes signature = 2; string key_id = 3; SignatureScheme scheme = 4; WebAuthnAssertion webauthn = 5;`. `scheme` is an enum (`SIGNATURE_SCHEME_UNSPECIFIED`, `_ED25519`, `_WEBAUTHN_ES256`) rather than the spec's string, so lint and switch statements are exhaustive.
- `WebAuthnAssertion`: `bytes authenticator_data = 1; bytes client_data_json = 2;`.

- [ ] **Step 4: Write `agent.proto`**

```protobuf
service AgentService {
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
  rpc EnrollAgent(EnrollAgentRequest) returns (EnrollAgentResponse);
  rpc StreamEvents(stream EventBatch) returns (StreamEventsResponse);
  rpc CommandStream(CommandStreamRequest) returns (stream SignedCommand);
  rpc ReportCommandResult(ReportCommandResultRequest) returns (ReportCommandResultResponse);
}
```
- `HeartbeatRequest`: `agent_id`, `timestamp`, `agent_version`, `uint64 rule_version`, `uint64 ioc_version`, `CollectorTier collector_tier` (`COLLECTOR_TIER_UNSPECIFIED`, `_A`, `_B`, `_C`).
- `HeartbeatResponse`: `AgentStatus status`, `google.protobuf.Timestamp server_time`. `AgentStatus` keeps the current four values.
- `EnrollAgentRequest`: `token`, `bytes csr_der`, `hostname`, `agent_version`. `EnrollAgentResponse`: `agent_id`, `bytes certificate_der`, `bytes ca_chain_der`.
- `StreamEventsResponse`: `uint64 last_batch_seq`. `CommandStreamRequest`: `agent_id`.
- `ReportCommandResultRequest`: `command_id`, `TurretResult result`, `detail`. Response is empty.

- [ ] **Step 5: Write `ipc.proto`**

- `ReflexRequest`: `request_id`, `Action action`, `target`, `int64 ttl_seconds`, `int32 pid`, `exe_path`, `rule_id`.
- `TurretRequest`: `oneof kind { ReflexRequest reflex = 1; SignedCommand signed = 2; }`.
- `TurretResult`: `TURRET_RESULT_UNSPECIFIED`, `_APPLIED`, `_REFUSED_SAFETY`, `_REFUSED_SIGNATURE`, `_REFUSED_REPLAY`, `_REFUSED_BUDGET`, `_FAILED`.
- `TurretResponse`: `id` (request_id or command_id), `TurretResult result`, `detail`.
- `TurretResult` is defined in `ipc.proto` and imported by `agent.proto`.

- [ ] **Step 6: Makefile targets**

- `proto`: `buf generate`.
- `proto-lint`: `buf lint`.
- `proto-check`: `buf lint && buf generate && git diff --exit-code -- pkg/synapse`.
- `dev-deps` adds `github.com/bufbuild/buf/cmd/buf@v1.50.0` and `github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8`. Pin the protoc plugins to the versions in `go.mod` (`google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11`, `google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.0` or the latest tagged release compatible with grpc v1.79.2) instead of `@latest`.

- [ ] **Step 7: Verify**

Run: `make dev-deps && make proto-lint && make proto && CGO_ENABLED=0 go build ./pkg/...`
Expected: lint prints nothing, and the build exits 0.

- [ ] **Step 8: Commit** (`feat(synapse): add v1 protobuf contracts`)

---

### Task 2: Event validation

**Files:**
- Create: `pkg/synapse/v1/validate.go`, `pkg/synapse/v1/validate_test.go`

**Interfaces:**
- Consumes: `Event` from Task 1.
- Produces: `func ValidateEvent(e *Event) error`, with exported errors `ErrMissingField`, `ErrAttrsTooMany`, `ErrAttrValueTooLong`, `ErrRawExcerptTooLong` (use them with `errors.Is`). Constants `MaxAttrs = 16`, `MaxAttrValueBytes = 256`, `MaxRawExcerptBytes = 512`.

- [ ] **Step 1: Write failing tests**

`TestValidateEvent` table cases:
- valid minimal event (`event_id`, `time`, `agent_id`, `class = AUTHENTICATION`, `severity = LOW`) → `nil`
- empty `event_id` → `ErrMissingField`
- nil `time` → `ErrMissingField`
- `class = UNSPECIFIED` → `ErrMissingField`
- 17 attrs → `ErrAttrsTooMany`; 16 attrs → `nil`
- an attr value of 257 bytes → `ErrAttrValueTooLong`; 256 bytes → `nil`
- `raw_excerpt` of 513 bytes → `ErrRawExcerptTooLong`; 512 bytes → `nil`

- [ ] **Step 2: Run** `go test ./pkg/synapse/v1/ -run TestValidateEvent` → FAIL (undefined)
- [ ] **Step 3: Implement** `ValidateEvent`. Wrap the errors with the field name (`fmt.Errorf("%w: event_id", ErrMissingField)`). Lengths are in bytes, not runes.
- [ ] **Step 4: Run** → PASS
- [ ] **Step 5: Commit** (`feat(synapse): validate event size limits`)

---

### Task 3: Reflex IPC framing

**Files:**
- Create: `pkg/synapse/v1/frame.go`, `pkg/synapse/v1/frame_test.go`

**Interfaces:**
- Produces: `const MaxFrameBytes = 65536`; `func WriteFrame(w io.Writer, m proto.Message) error`; `func ReadFrame(r io.Reader, m proto.Message) error`; `var ErrFrameTooLarge`. Phase 1 (Turret) and Phase 2 (Sentry) use these over `/run/watchtower/turret.sock`.

- [ ] **Step 1: Write failing tests**
- `TestFrameRoundTrip`: write a `TurretRequest{reflex: …}` to a `bytes.Buffer`, read it into a new message, and assert `proto.Equal`.
- `TestReadFrameRejectsOversizedLength`: the header says `65537` → `ErrFrameTooLarge`, and the reader never allocates more than 4 bytes (assert with a reader that returns only the header and then `io.EOF`; the error must be `ErrFrameTooLarge`, not `io.ErrUnexpectedEOF`).
- `TestReadFrameTruncatedBody`: the header says 10 and the body has 3 bytes → `io.ErrUnexpectedEOF`.
- `TestWriteFrameRejectsOversizedMessage`: a message that marshals to more than 65536 bytes → `ErrFrameTooLarge`, and nothing is written.
- `TestReadFrameEmptyStream`: an empty reader → `io.EOF` (a clean close).
- [ ] **Step 2: Run** → FAIL
- [ ] **Step 3: Implement** with `encoding/binary.BigEndian` and `io.ReadFull`. Check the length against `MaxFrameBytes` before allocating.
- [ ] **Step 4: Run** `go test -race ./pkg/synapse/v1/` → PASS
- [ ] **Step 5: Commit** (`feat(synapse): length-prefixed IPC framing`)

---

### Task 4: SQL migrations and migrator

**Files:**
- Create: `deployments/sql/embed.go`, `deployments/sql/bootstrap.sql`, `deployments/sql/migrations/0001_fleet.sql` (agents, enrollment_tokens, certificates), `0002_telemetry.sql` (events, detections, with hypertables and policies), `0003_response.sql` (incidents, response_actions, pending_approvals, admin_keys), `0004_analytics.sql` (baselines, ip_reputation, ioc_indicators, correlation_state), `0005_audit.sql` (audit_logs), `0006_grants.sql`
- Create: `internal/core/store/migrate.go`, `internal/core/store/migrate_test.go`
- Modify: `go.mod` (add `github.com/jackc/pgx/v5`)

**Interfaces:**
- Produces:
  - `package sqlmigrations`: `//go:embed bootstrap.sql migrations/*.sql` → `var FS embed.FS`
  - `func Bootstrap(ctx context.Context, conn *pgx.Conn) error`: runs `bootstrap.sql`. It needs a superuser and is idempotent.
  - `func Migrate(ctx context.Context, conn *pgx.Conn, fsys fs.FS) ([]string, error)`: returns the versions it applied, in order.

Table definitions are copied verbatim from spec §4.3. The SQL comments in §4.3 that create roles move into `bootstrap.sql`.

- [ ] **Step 1: Write `bootstrap.sql`**

`CREATE EXTENSION IF NOT EXISTS timescaledb;`. Create roles `wt_owner NOLOGIN`, `wt_core LOGIN` and `wt_grafana LOGIN` only if they are missing (`DO $$ … IF NOT EXISTS (SELECT 1 FROM pg_roles …) $$`). Set no passwords. `GRANT CREATE, USAGE ON SCHEMA public TO wt_owner; GRANT USAGE ON SCHEMA public TO wt_core, wt_grafana; GRANT wt_owner TO CURRENT_USER;` (lets the migrating user `SET ROLE wt_owner`).

- [ ] **Step 2: Write failing tests** (skip unless `WT_TEST_DATABASE_URL` is set; each test creates and drops a fresh database named `wt_test_<random>`)
- `TestMigrateFreshDatabase`: after `Bootstrap` and `Migrate`, all 14 tables from §4.3 exist, and `timescaledb_information.hypertables` lists `events` and `detections`. The returned versions are `0001_fleet` … `0006_grants`.
- `TestMigrateIsIdempotent`: a second `Migrate` returns an empty slice and no error.
- `TestTablesOwnedByWtOwner`: every table in `public` has `tableowner = 'wt_owner'` (via `pg_tables`).
- `TestAuditLogAppendOnly`: after `SET ROLE wt_core`, an `INSERT` into `audit_logs` succeeds, while `UPDATE`, `DELETE` and `TRUNCATE` each fail with SQLSTATE `42501` (insufficient_privilege).
- `TestMigrateFailedFileRollsBack`: given an `fstest.MapFS` with `0001_ok.sql` (creates table `a`) and `0002_bad.sql` (creates table `b`, then has invalid SQL), `Migrate` returns an error, table `a` exists, table `b` does not, and `schema_migrations` contains only `0001_ok`.
- `TestMigrateWithoutOwnerRole`: connected as a role that is not a member of `wt_owner`, `Migrate` returns an error whose message contains `wt_owner`, and creates nothing.

- [ ] **Step 3: Run** `WT_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres go test ./internal/core/store/` → FAIL. To start a local DB: `docker run -d --rm -p 5432:5432 -e POSTGRES_PASSWORD=postgres timescale/timescaledb:2.17.2-pg16`.
- [ ] **Step 4: Implement**

`Migrate` steps:
1. `pg_advisory_lock(727274)` (any fixed key; release it with defer).
2. `CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`, created as `wt_owner`.
3. Sort the files in `migrations/*.sql` lexically.
4. For each pending file, in one transaction: `SET LOCAL ROLE wt_owner` → exec the file → insert the version, where the version is the file name without `.sql`.

- [ ] **Step 5: Run** → PASS
- [ ] **Step 6: Commit** (`feat(store): schema migrations with owner/runtime role split`)

---

### Task 5: Rules layout and structural check

**Files:**
- Create: `rules/README.md`, `rules/wes-mapping.yaml`, `rules/agent/linux/sshd/ssh_auth_failure.yml`, `ssh_auth_failure.samples.yml`, `ssh_brute_force.yml`, `ssh_brute_force.samples.yml`
- Create: `internal/rules/spec.go`, `internal/rules/spec_test.go`

**Interfaces:**
- Produces: `type Rule struct { Path, Title, ID, Level, Scope string; Fields []string; Correlates []string }`. `func LoadDir(fsys fs.FS) ([]Rule, error)` parses every `*.yml` that isn't `*.samples.yml` (multi-document YAML is allowed). `func ValidateRules(rules []Rule, mapping map[string]string, fsys fs.FS) error`. `func LoadMapping(fsys fs.FS) (map[string]string, error)` reads `wes-mapping.yaml` (Sigma field name → WES field path).

The two rules are the example from spec §4.2, split into one file per rule. `wes-mapping.yaml` maps at least `class`, `auth.service`, `auth.outcome`, `src.ip`, `user.name`, `process.exe`, `process.cmdline`, `file.path`, `http.path`, `http.status`. Sample files have the form `match: [<event>, …]` and `no_match: [<event>, …]`, where events are WES field maps. In Phase 0 they are only checked for presence and parseability; the matching engine arrives in Phase 2.

- [ ] **Step 1: Write failing tests**
- `TestRepositoryRulesAreValid`: `LoadDir(os.DirFS("../../rules"))` and `ValidateRules` → no error, with ≥ 2 rules.
- `TestValidateRules` table cases:
  - duplicate `id` → error naming both paths
  - an `id` that isn't a UUID → error
  - `level` not in {informational, low, medium, high, critical} → error
  - `custom.scope` not in {agent, core} → error
  - a detection field missing from the mapping → error naming the field
  - a correlation referencing an unknown rule `id` → error
  - a missing `.samples.yml` sibling → error
- [ ] **Step 2: Run** → FAIL
- [ ] **Step 3: Implement.** Collect field names from the keys under `detection.*` selections and strip Sigma modifiers (`field|contains` → `field`). Read `Scope` from `custom.scope`, defaulting to `agent` if absent.
- [ ] **Step 4: Run** → PASS
- [ ] **Step 5: Commit** (`feat(rules): rule layout, WES mapping and structural validation`)

---

### Task 6: Move binaries onto `pkg/synapse`

**Files:**
- Modify: `cmd/wt-core/main.go`, `cmd/wt-sentry/main.go`
- Rename: `test/integration/phase0_test.go` → `test/integration/heartbeat_test.go`
- Delete: `pkg/protocol/`, `cmd/wt-interceptor/`, `scripts/verify-phase0.sh`
- Modify: `Makefile` (remove `run-interceptor` and the interceptor entry in `clean`), `.gitignore` (remove `/wt-interceptor`), `.goreleaser.yml` (drop the interceptor build, if listed)

**Interfaces:**
- Consumes: `synapsev1.AgentServiceServer` / `Client`, `HeartbeatRequest`, and `HeartbeatResponse` from Task 1.

- [ ] **Step 1: Update the integration test first.** In `TestHeartbeatFlow`, also assert that Core's log line includes `version=` and `tier=` (Core logs `agent_version` and `collector_tier`). Set `WT_HEARTBEAT_INTERVAL=1s` in the test itself (`t.Setenv` applies to the child processes started with `exec.Command` because they inherit the env), so the test takes about 10 s instead of about 67 s.
- [ ] **Step 2: Run** `go test ./test/integration/` → FAIL (log fields missing)
- [ ] **Step 3: Implement.**
  - Core embeds `synapsev1.UnimplementedAgentServiceServer` (the new RPCs return `codes.Unimplemented`) and logs `agent_id`, `version`, `tier`. The response includes `server_time`.
  - Sentry sends `agent_version` (from the `Version` ldflag variable) and `collector_tier = COLLECTOR_TIER_C`.
- [ ] **Step 4: Run** `go test ./test/integration/ && CGO_ENABLED=0 go build ./... && grep -r "pkg/protocol" --include=*.go . ; test $? -eq 1` → PASS, and no references to `pkg/protocol` remain.
- [ ] **Step 5: Commit** (`refactor: move heartbeat onto synapse v1, drop interceptor`)

---

### Task 7: CI gates and documentation

**Files:**
- Modify: `.github/workflows/ci.yml`, `Makefile` (`verify` target), `CHANGELOG.md`, `README.md`, `docs/architecture.md` (§2.3 and §5.2)

- [ ] **Step 1: Replace `ci.yml` with five jobs on `push`/`pull_request` to `master`:**
  - `lint`: `golangci/golangci-lint-action@v6` with `version: v1.64.8`.
  - `proto`: install buf v1.50.0 and the pinned plugins → `make proto-check`.
  - `build`: `CGO_ENABLED=0 go build ./...`.
  - `test`: `go test -race ./internal/... ./pkg/...`, then `go test ./test/integration/`.
  - `migrations`: service `timescale/timescaledb:2.17.2-pg16` (`POSTGRES_PASSWORD=postgres`, health check `pg_isready`), env `WT_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres` → `go test -race ./internal/core/store/`.
- [ ] **Step 2: Add `make verify`.** It runs `proto-check`, a `CGO_ENABLED=0` build, `lint`, and `test` in that order, so you can run the CI gate locally with one command.
- [ ] **Step 3: Update the docs.**
  - CHANGELOG: under `[Unreleased]`, replace "In Progress" with Phase 0 `Added` / `Removed` entries.
  - README: tick Phase 0 only after CI is green on the PR, and replace `./scripts/verify-phase0.sh` in Quick Start with `make verify`.
  - architecture §2.3: add a note that `.proto` sources live in `proto/watchtower/synapse/v1/` and the generated code in `pkg/synapse/v1/`.
  - architecture §5.2: show `scheme` as the `SignatureScheme` enum and include the `webauthn` field.
- [ ] **Step 4: Verify.** `make verify` passes locally. Push the branch, and all five CI jobs pass on the PR.
- [ ] **Step 5: Commit** (`ci: enforce Phase 0 gates`)

---

## Phase 0 exit gate (spec §7)

- `buf lint` is clean and `make proto-check` leaves no diff
- `CGO_ENABLED=0 go build ./...` exits 0
- the migration tests pass against a fresh TimescaleDB in CI
- lint, unit tests (with `-race`) and the integration test pass in CI
- CHANGELOG and README are updated, and the version is tagged `v0.3.0` after merge
