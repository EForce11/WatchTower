# Phase 2 (`wt-sentry`) — Inputs and Open Problems

**Status:** input for the Phase 2 design and plan. This is not a plan: it collects the environment and portability problems found while designing Phase 1.5, so the Phase 2 work can address them deliberately.
**Date:** 2026-11-27
**Spec:** `docs/architecture.md` v3.3, §3.3 (Sentry), §3.4.6 (Turret capabilities, for contrast), §7 Phase 2, §9.

## Context: decisions already taken (v3.3)

- **Sentry is a sensor only.** It never triggers an action, local or remote. The Reflex Arc is gone; Turret accepts only Core-signed commands.
- **Everything is decided by Core.** Sentry's job is to tell Core accurately what is happening *and what the host is*, so that Core's decisions fit the host.
- **Target users include self-hosters.** Installing an agent must not be a project in itself. Sentry has to work on the common self-hosting platforms without per-host tuning, and it has to say clearly when it cannot see something.
- **Turret checks its own capabilities** (§3.4.6); Sentry does not do that for it. Sentry is unprivileged and untrusted, so it cannot vouch for Turret.

## 1. Host inventory (new responsibility)

Core needs to know what each host is and runs. Sentry collects a snapshot at start and then periodically, and emits change events.

| Item | Source | Notes |
|---|---|---|
| Distribution and version | `/etc/os-release` | Debian, Ubuntu, RHEL/Rocky/Alma, Fedora, Arch, Alpine, NixOS… |
| Kernel | `uname` (syscall), `/proc/sys/kernel/osrelease` | Also useful context for Turret's capability report |
| Init system | `/proc/1/comm` (`systemd`, `openrc-init`/`init`, `runit`) | Sentry must not assume systemd |
| Package manager | presence of `/var/lib/dpkg`, the rpm db, `/var/lib/pacman`, `/lib/apk/db` | Drives package verification (§3) |
| Listening sockets | `/proc/net/{tcp,tcp6,udp,udp6}` (state LISTEN, owner UID) | Process attribution for other users' sockets needs Tier A (eBPF) or root; without it, report port + owner UID |
| Services | systemd: D-Bus (`org.freedesktop.systemd1`, pure Go client) or unit files under `/etc/systemd`, `/usr/lib/systemd`. OpenRC: `/etc/init.d`, `/run/openrc` | Decide D-Bus vs. file scan (open question Q2) |
| Container runtimes | sockets `/run/docker.sock`, `/run/podman/podman.sock`, `/run/containerd`; cgroup paths under `/sys/fs/cgroup` | Unprivileged Sentry usually cannot query the Docker API (root-owned socket); cgroup and `/proc` give container attribution of processes |
| Published container ports | the runtime API, if its socket is readable; reading the host's DNAT rules is **not** possible unprivileged | Important for Core: "port 443 → Nextcloud container" |
| Installed software changes | `dpkg.log`, `/var/log/pacman.log`, dnf/yum history, apk db mtime | Emits `software_change` events. Also used as maintenance-window context for FIM: context only, it never lowers severity (§3.3.2) |

**Output:** a WES event class for inventory (e.g. `host_inventory` snapshot plus `inventory_change` deltas). This is a contract change in `pkg/synapse`, so it should be decided early in Phase 2.

## 2. Log sources

| Problem | Affected | Options |
|---|---|---|
| `/var/log/auth.log` does not exist; logs live only in **journald** | Arch, modern Fedora, minimal Debian/Ubuntu without rsyslog | (a) Pure-Go journal file reader. `coreos/go-systemd/sdjournal` needs cgo, so it is excluded. (b) Run `journalctl -o json --follow` as a subprocess; this conflicts with the current "Sentry never spawns tools" rule, so it needs an explicit exception. (c) Require rsyslog. **Decide (Q1).** journald must be a first-class source. |
| `/var/log/secure` is `root:root 0600` | RHEL/Rocky | The installer adds an ACL or group, or the source is reported as unreadable |
| Reading the journal needs group `systemd-journal`; `adm` semantics differ per distro | systemd distros, Arch | Per-distro group setup in the installer (Phase 8); `doctor` reports it |
| Docker container logs (`/var/lib/docker/containers/*/*-json.log`) are root-only | Docker hosts | Out of reach for unprivileged Sentry. Options: a log driver to syslog/journald (documented), or accept the gap. **Decide (Q3).** |
| Web server logs in non-default paths or inside containers | everyone | Configurable source list; autodetect common paths and say what was found |

## 3. Package verification (FIM)

The spec only covers `dpkg` and `rpm`. On other systems every update would look like "an unowned file changed", which is a high-severity false positive storm.

| Manager | Manifest | Notes |
|---|---|---|
| dpkg | `/var/lib/dpkg/info/*.md5sums` | in spec |
| rpm | rpmdb (BerkeleyDB, NDB or **SQLite** on RHEL 9/Fedora) | the pure-Go reader must handle all three formats; verify that `knqyf263/go-rpmdb` really stays cgo-free for SQLite |
| pacman | `/var/lib/pacman/local/<pkg>/mtree` (gzip, sha256) | new adapter |
| apk | `/lib/apk/db/installed` (`Z:` sha1 per file) | new adapter |
| unknown / NixOS | — | Package verification is **disabled and reported**, and FIM still reports changes at a neutral severity. It must never default to "unowned ⇒ high". |

## 4. Privileges, groups and limits

- The `watchtower` user plus the right read groups differ per distro (`adm`, `systemd-journal`, `wheel`…). The installer must handle this, and `wt-sentry doctor` must show which sources are unreadable and why.
- `fs.inotify.max_user_watches` can be too low for FIM on large trees; `doctor` should check and recommend.
- The optional Tier A (`CAP_BPF`, `CAP_PERFMON`) and Tier B (auditd `log_group`) setups differ per distro.
- Containers and VMs: Sentry inside a container sees only that container. Host-level monitoring of containers needs the host Sentry plus cgroup attribution.

## 5. Sentry ↔ Turret after v3.3

- Sentry only **forwards** Core-signed commands to Turret over the socket. It never originates one.
- IOC matches, including in temp dirs, become `critical` detections to Core. Core may send back a signed `KILL_TEMP_MALWARE`.
- Turret's Flood Guard offender events (`<state_dir>/flood-events.jsonl`, root-owned) need a path to Core. Either Sentry reads them (permissions!) or Turret exposes them on its socket. **Decide (Q4).**

## 6. `wt-sentry doctor`

This mirrors `wt-turret doctor`: one command right after install that lists every source and capability as ✔/✖ with a reason, for example:

- distro and init system
- which log sources are readable
- package manager detected and verification on/off
- collector tier A/B/C
- container runtime seen
- inotify headroom

Exit codes: `0` ok, `1` degraded, `2` cannot run.

## 7. Platform matrix to confirm

| Platform | Expectation to confirm in Phase 2 |
|---|---|
| Debian 11/12, Ubuntu 20.04–24.04 | full |
| RHEL/Rocky/Alma 8–9, Fedora | full (rpm SQLite on 9+, `/var/log/secure` permissions) |
| Arch | full only with journald support and the pacman adapter |
| Alpine (OpenRC, apk, often no syslog by default) | partial until the apk adapter and OpenRC service files exist |
| NixOS | sensor without package verification |
| OpenVZ / unprivileged LXC | Sentry works (Turret is observe-only there, §3.4.6) |

## Open questions

- **Q1 — journald access:** a pure-Go journal reader, a sanctioned `journalctl` subprocess, or requiring rsyslog?
- **Q2 — services inventory:** a D-Bus client (pure Go, a new dependency) or unit-file scanning only?
- **Q3 — Docker container logs:** document a syslog/journald log driver, add an optional privileged helper, or accept the gap?
- **Q4 — Flood Guard events to Core:** does Sentry read Turret's event file, or does Turret serve the events on its socket?
- **Q5 — inventory contract:** what is the shape of the `host_inventory` and `inventory_change` WES classes, and how often are snapshots taken?
- **Q6 — supported platforms:** which rows of §7 are "tier 1", meaning tested in CI with a container or VM per distro?
