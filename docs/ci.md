# CI

What each CI job guarantees, what environment it assumes, and how to run it locally. The workflow is `.github/workflows/ci.yml`. CodeQL runs separately in `.github/workflows/codeql.yml`.

## Jobs

| Job | Guarantees | Local equivalent |
|---|---|---|
| **Lint** | golangci-lint v1.64.8 (v1 config) is clean. It includes `gofmt`/`goimports` and lints the `netns` build tag. | `make lint` |
| **Tidy** | `go.mod` and `go.sum` are exactly what `go mod tidy` produces. | `go mod tidy && git diff --exit-code -- go.mod go.sum` |
| **Proto** | `buf lint` (STANDARD) is clean, and regenerating `pkg/synapse/v1` with the pinned plugins changes nothing and leaves no untracked file. | `make proto-check` |
| **Build** | Every binary builds with `CGO_ENABLED=0`. `.goreleaser.yml` passes `goreleaser check`. | `CGO_ENABLED=0 go build ./...` |
| **Vulnerabilities** | `govulncheck` finds no known vulnerability **reachable from our code** in dependencies or the standard library. | `go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...` |
| **Test** | Unit tests pass under `-race`. The heartbeat integration test (real `wt-core` + `wt-sentry` binaries) passes. | `go test -race ./internal/... ./pkg/... ./cmd/wt-turret/ && go test ./test/integration/` |
| **Migrations (PostgreSQL 14, 16)** | The schema migrates on a fresh TimescaleDB 2.17.2 and passes the role and privilege tests on both the minimum and the current PostgreSQL. | see below |
| **Netns** | The nftables firewall and the `wt-turret` smoke test pass against the **real kernel** inside an unprivileged user + network namespace. | `make test-netns` |

`make verify` runs Proto, Build (without goreleaser), Lint, Test and, when user namespaces are available, Netns.

## No silent skips

Tests that depend on the environment (memfd exec, root vs non-root, …) skip through `internal/testenv.Skip`. The Test, Migrations and Netns jobs set `WT_NO_SKIP=1`, which turns every such skip into a **failure**. A test that stops running in CI therefore shows up red instead of looking like a pass. The migration tests additionally use `WT_REQUIRE_DB=1`, which fails when `WT_TEST_DATABASE_URL` is missing.

Locally, skips stay skips unless you set `WT_NO_SKIP=1` yourself.

## Environment assumptions

- **Runner:** `ubuntu-latest` (x86-64, little-endian; `/proc/net/route` parsing relies on this), non-root user with passwordless `sudo`.
- **Go:** the version from `go.mod` (`toolchain` line), installed by `setup-go`.
- **Netns job:**
  - Ubuntu 24.04 blocks unprivileged user namespaces through AppArmor, so the job sets `kernel.apparmor_restrict_unprivileged_userns=0`.
  - It loads `nf_tables`.
  - It logs `uname -r`, because nftables behaviour can differ by kernel.
  - The namespace has **no network**. Modules and the toolchain are fetched beforehand, and `make test-netns` runs with `GOPROXY=off` so a missing dependency fails fast.
  - The packages run serially (`-p 1`) because they share one nftables namespace.
- **Migrations job:**
  - Uses the `timescale/timescaledb:2.17.2-pg<N>` service on `localhost:5432` (password `postgres`, test-only).
  - Each test creates and drops its own database.

Local migration run:

```bash
docker run -d --rm --name wt-pg -p 5432:5432 -e POSTGRES_PASSWORD=postgres timescale/timescaledb:2.17.2-pg16
WT_TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' WT_REQUIRE_DB=1 go test -race ./internal/core/store/
docker stop wt-pg
```

## Supply chain and token

- Third-party actions are pinned to a **commit SHA**, with the tag in a trailing comment. Dependabot (`.github/dependabot.yml`, ecosystem `github-actions`) proposes updates.
- `golangci-lint-action` stays on v6, because v7+ only supports golangci-lint v2. Migrating the lint config to v2 is a separate change.
- `permissions: contents: read` at workflow level; no job gets write access. CodeQL alone adds `security-events: write`.
- `concurrency` cancels a superseded run when a PR is pushed again.
- Every job has a `timeout-minutes`.

## Branch protection (repository setting, done by a maintainer)

CI only blocks a merge if `master` requires it. In **Settings → Branches → Add rule** for `master`:

- Require a pull request before merging.
- Require status checks to pass, and mark these as required:
  - `Lint`
  - `Tidy`
  - `Proto`
  - `Build`
  - `Vulnerabilities`
  - `Test`
  - `Migrations (PostgreSQL 14)`
  - `Migrations (PostgreSQL 16)`
  - `Netns`
  - `Analyze (go)`
- Require branches to be up to date before merging.
- Do not allow bypassing, and block force pushes and deletions.

## Known gaps

- **Timing-based tests.** The netns ban-expiry tests sleep a few seconds. A heavily loaded runner can make them flaky; rerun once, and treat a repeat failure as real.
- **Hardware and distribution coverage.** Only one kernel and distribution (the runner's) is tested; there is no arm64 runner.
- **Release workflow.** There is none yet. `goreleaser check` validates the config but nothing builds or publishes artifacts.
