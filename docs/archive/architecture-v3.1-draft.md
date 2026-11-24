# 🏛️ WatchTower XDR - System Design Document v3.1 (NEURO-ARCHITECTURE & TRUE XDR REORGANIZATION)

**Project Status:** Pre-Alpha, Single-Maintainer, Active Development ⚠️ | Code: Pre-Release (`v0.2.0` -> `v3.1` Architectural Transition)  
**Last Updated:** 2026-11-06 (Complete Neuro-Architectural Naming: `Synapse`, `Reflex Arc`, `Hippocampus`, `Frontal`, `Midbrain`; CSR-based PKI; Read-Only FIM)  
**Architect & Developer:** Emir Furkan Ulu  
**Vision:** "Simple setup, zero self-inflicted outage risk, explainable XDR powered by deterministic math and isolated cognitive AI."

---

## 🔍 Version History (v2.2 → v3.1 Radical Architectural Revision) ⭐ CURRENT

All OS-bricking risks, undocumented dependencies, and scope creep identified during the v2.2 Red Team audit have been eliminated. The system is now structured around a strict, biologically inspired **Neuro-Architecture** and true enterprise XDR/SOAR principles:

1. 🧠 **Complete Neuro-Architectural Naming Standard:** Server and agent modules, internal memory packages, and communication protocols are mapped directly to biological nervous system functions:
   - **`wt-core` (Brainstem):** Autonomous life functions, gRPC backbone, TimescaleDB writer, and Deterministic Policy Engine.
   - **`internal/core/hippocampus` (Hippocampus):** Short-to-long-term spatial/temporal memory; manages the In-Memory Seasonal Baseline Cache (`agent:metric:dow:hour`) and `<1ms` Z-Score anomaly calculations.
   - **`wt-frontal` (Frontal Cortex):** Isolated AI SOC, cross-layer correlation reasoning, and schema-enforced `ActionProposal` service.
   - **`wt-midbrain` (Midbrain - v1.5 Target):** Cyber Threat Intelligence (CTI) aggregator pulling O(1) lookup IOCs (SHA256 malware hashes and C2 IPs) from external feeds.
   - **`wt-sentry` (Sensory Nerves):** Unprivileged, read-only telemetry agent collecting logs, FIM events, IOC matches, and `/proc` metrics.
   - **`wt-turret` (Motor Nerves & Muscle):** Privileged execution daemon managing `ipset`/`iptables` and verified process termination.
   - **`pkg/synapse` (Synapse):** Unified communication contract package containing both remote gRPC/Protobuf definitions and local Unix Socket IPC messages.
2. ⚡ **`REFLEX` (Spinal Reflex Arc) vs. `CORTEX_SIGNED` (Conscious Response) Separation:** 
   - **`Origin: "REFLEX"` (Fast Path):** The local `wt-sentry -> wt-turret` spinal arc is strictly limited to reversible network throttling (`TARPIT`, `BAN_TEMP` max 15m TTL) and stopping verified malware executables strictly inside `/tmp`, `/var/tmp`, or `/dev/shm` (`KILL_TEMP_MALWARE`).
   - **`Origin: "CORTEX_SIGNED"` (Slow Path):** High-impact actions (`BAN_PERM`, `KILL_PROCESS`, `ISOLATE_HOST`) must originate from the `wt-core` Policy Engine, carry a valid **Ed25519 cryptographic signature**, and—for destructive actions—require explicit administrator approval (**Human-in-the-Loop**) via `ntfy.sh` interactive webhooks.
3. 🛡️ **FIM "Quarantine" Hazard Eliminated:** The `wt-sentry` File Integrity Monitor (FIM) is strictly forbidden from moving (`mv`), deleting, or locking (`chattr +i`) files. Package-manager lock awareness (`dpkg`/`rpm` lock checks) prevents false-positive `L4` floods during routine OS updates.
4. 🔐 **Zero Private-Key Exposure PKI (CSR Model):** The `key_pem` column has been permanently removed from the PostgreSQL `certificates` table. Agents generate private keys locally (`0600`) and submit only CSRs (Certificate Signing Requests) to `wt-core`.
5. 🧹 **Undocumented Dependencies Purged (Zero CGo & No Redis):** Hidden Redis requirements and CGo/PyTorch bindings have been stripped (`CGO_ENABLED=0` globally). `wt-frontal` communicates with any OpenAI-compatible endpoint (OpenRouter, AWS Bedrock, Ollama, vLLM) over standard HTTP REST.
6. 🧱 **Adaptive Subnet Limiter (Unbreakable IPS):** Replaced the flawed circuit breaker (which shut down all IPS protection into `LOG_ONLY` mode after 10 bans/min) with an Adaptive `/24` IPv4 (and `/64` IPv6) Subnet Escalator.

---

## 📋 Table of Contents

1. [Executive Summary & Global Invariants](#1-executive-summary--global-invariants)
2. [Neuro-Architectural System Topology](#2-neuro-architectural-system-topology)
3. [Component Specifications](#3-component-specifications)
4. [Data Management & Database Schema](#4-data-management--database-schema)
5. [Security, PKI & Trust Boundaries](#5-security-pki--trust-boundaries)
6. [Operational Procedures & CLI](#6-operational-procedures--cli)
7. [Realistic Development Roadmap](#7-realistic-development-roadmap)

---

## 1. Executive Summary & Global Invariants

### 1.1 Project Vision
WatchTower XDR is a self-hosted, open-source Extended Detection and Response (XDR) platform engineered for small-to-medium server fleets, VPS deployments, and hybrid environments. Unlike standalone tools (Fail2Ban, OSSEC) that react blindly to isolated single-layer events, WatchTower correlates weak signals across network, application, and host layers while guaranteeing zero self-inflicted system outages.

### 1.2 Non-Negotiable Architectural Invariants
- **Zero CGo & Pure Go:** Every binary compiles with `CGO_ENABLED=0` (`Go 1.21+`) into a single static executable.
- **Self-Hosted First & Single Database:** Zero mandatory cloud dependencies. **PostgreSQL 14+ (with TimescaleDB)** is the sole data store on Core; Redis and external message brokers are strictly forbidden.
- **Fail-Safe by Construction:** No agent component has the authority to move, delete, or modify system binaries or configuration files.
- **Explainable & Pluggable AI:** `wt-frontal` (Frontal Cortex AI SOC) is 100% optional. The LLM never executes shell commands; it outputs strictly validated JSON proposals (`ActionProposal`) evaluated by the deterministic Policy Engine in `wt-core`.

### 1.3 Technology Stack (NON-NEGOTIABLE)

| Layer | Technology | Justification |
|-------|------------|---------------|
| **Language** | Go 1.21+ (`CGO_ENABLED=0`) | Single static binary, low memory (~50MB), native concurrency |
| **Synaptic IPC (Remote)** | gRPC + Protobuf (`pkg/synapse`) | Type-safe, bi-directional streaming, native mTLS support |
| **Synaptic IPC (Local)** | Unix Domain Sockets (`pkg/synapse`) | `/run/watchtower/turret.sock` (`0660`), zero network overhead |
| **Database & Memory** | PostgreSQL 14+ & TimescaleDB | ACID compliance, automated time-series hypertables & compression |
| **Network Enforcement** | `iptables` + `ipset` | O(1) kernel-level IP and `/24` subnet blocking |
| **AI SOC Client** | OpenAI-Compatible HTTP REST | Works with OpenRouter, AWS Bedrock, Ollama, vLLM, or local GGUF servers |
| **Notifications & ChatOps** | `ntfy.sh` (Interactive Webhooks) | Self-hostable push notifications with **[Approve / Reject]** action buttons |
| **Dashboard** | Grafana 10+ | Native PostgreSQL/TimescaleDB data source, zero custom UI maintenance |
| **Management Network** | WireGuard VPN | Kernel-integrated, low-overhead encrypted administrative plane |

---

## 2. Neuro-Architectural System Topology

### 2.1 High-Level Architecture Diagram

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                   PROTECTED SERVER (PERIPHERAL NERVOUS SYSTEM)          │
│                                                                         │
│  ┌───────────────────────────────────┐                                  │
│  │ wt-sentry (Sensory Nerves)        │  Unprivileged User: watchtower   │
│  │ - fsnotify LogWatcher (Sliding W.)│  - Read-Only FIM (dpkg lock aware│
│  │ - /proc Metric & TCP Collector    │  - O(1) Midbrain IOC Matcher     │
│  │ - Amygdala Decoy Watcher (v2.0)   │                                  │
│  └────────┬─────────────────────────┬┘                                  │
│           │ Reflex Arc (Unix Socket)│ Synaptic Telemetry Stream &       │
│           │ Origin: "REFLEX"        │ Origin: "CORTEX_SIGNED" Commands  │
│           ▼ /run/watchtower/turret.sock (0660)                          │
│  ┌──────────────────────────────────┐│                                  │
│  │ wt-turret (Motor Nerves / Muscle)││  Privileges: root / CAP_NET_ADMIN│
│  │ - Whitelist & Self-Preservation  ││  - Adaptive /24 Subnet Limiter   │
│  │ - ipset (wt_temp_ban, wt_perm)   ││  - Ed25519 Signature Verifier    │
│  │ - /proc/<PID>/exe Verified Kill  ││                                  │
│  └──────────────────────────────────┘│                                  │
└──────────────────────────────────────┼──────────────────────────────────┘
                                       │ pkg/synapse (gRPC / mTLS :50051)
                                       │ Bi-Directional Streaming
┌──────────────────────────────────────▼──────────────────────────────────┐
│                 MANAGEMENT NETWORK (CENTRAL NERVOUS SYSTEM)             │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ wt-core (Brainstem)                                               │  │
│  │ - gRPC Server (CSR Enrollment, Heartbeat, Telemetry, CommandStream│  │
│  │ - Hippocampus (internal/core/hippocampus): Baseline Cache & Z-Scor│  │
│  │ - Multi-Layer Incident Correlator (5-min Sliding Window)          │  │
│  │ - Deterministic Policy Engine & Ed25519 Command Signer            │  │
│  └──────┬────────────────────────────┬─────────────────────────┬─────┘  │
│         │ SQL (pgx)                  │ gRPC (Localhost)        │ gRPC   │
│         ▼                            ▼                         ▼        │
│  ┌─────────────────────┐  ┌──────────────────────┐  ┌─────────────────┐ │
│  │ PostgreSQL 14 +     │  │ wt-frontal           │  │ wt-midbrain     │ │
│  │ TimescaleDB         │  │ (Frontal Cortex)     │  │ (Midbrain CTI)  │ │
│  │ - events (Hypertable│  │ - Prompt Sanitizer   │  │ - Abuse.ch /    │ │
│  │ - baselines         │  │ - OpenAI/vLLM Client │  │   MalwareBazaar │ │
│  │ - pending_approvals │  │ - Strict JSON Schema │  │ - O(1) IOC Sync │ │
│  │ - audit_logs (WORM) │  │ - ActionProposal     │  │   (SHA256 / IP) │ │
│  └─────────────────────┘  └──────────────────────┘  └─────────────────┘ │
└──────────────────────────────────────┬──────────────────────────────────┘
                                       │ WireGuard VPN (10.8.0.0/24)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                  ADMINISTRATOR PLANE (CONSCIOUS OVERRIDE)               │
│  - Mobile (ntfy.sh): Interactive [Approve] / [Reject] for L4 Actions    │
│  - Workstation: wt-cli, Grafana Dashboard (Port 8080)                   │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Synaptic Communication Matrix (`pkg/synapse`)

| Source | Destination | Transport / Path | Auth / Verification | Purpose |
|--------|-------------|------------------|---------------------|---------|
| `wt-sentry` | `wt-turret` | Unix Socket (`/run/watchtower/turret.sock`) | File Perms (`0660`) + `Origin` Check | `REFLEX` actions (`TARPIT`, `BAN_TEMP`, `KILL_TEMP_MALWARE`) & `CORTEX_SIGNED` forwarding |
| `wt-sentry` | `wt-core` | gRPC / TLS (`50051`) | mTLS + Bearer Token | Telemetry streaming, Heartbeat, receiving `CORTEX_SIGNED` commands via `CommandStream` |
| `wt-core` | `wt-frontal` | gRPC (`127.0.0.1:50052`) | mTLS / Loopback | Sending correlated `IncidentContext` and receiving `ActionProposal` |
| `wt-frontal` | LLM Provider | HTTPS / HTTP | Bearer API Key | Schema-constrained inference via OpenRouter, Bedrock, Ollama, or vLLM |
| `wt-core` | `wt-midbrain` | gRPC (`127.0.0.1:50053`) | mTLS / Loopback | Synchronizing verified O(1) IOC bundles (SHA256 hashes & C2 IPs) |
| `wt-core` | Admin (`ntfy`) | HTTPS Webhook | Token + HMAC | Human-in-the-Loop approval requests for destructive actions |

---

## 3. Component Specifications

### 3.1 `wt-core` (The Brainstem) & `Hippocampus`

**Binary Name:** `wt-core`  
**Resource Target:** 512MB - 2GB RAM, 1-2 CPU Cores (`CGO_ENABLED=0`)

1. **`Hippocampus` (`internal/core/hippocampus` — Seasonal Memory & Baseline Cache):**
   - Models spatial and temporal memory by caching 7-day seasonal baselines (`agent_id:metric:dow:hour`) in an in-memory map (`map[string]*Baseline` protected by `sync.RWMutex`).
   - Refreshes asynchronously from TimescaleDB every 10 minutes, computing Z-Scores (`z = (current - avg) / stddev`) in `<1ms` with zero database bottleneck during event spikes.
2. **Multi-Layer Incident Correlator (`internal/core/correlator`):**
   - Aggregates weak signals across network, web, and host layers per `SourceIP` and `AgentID` over a 5-minute sliding window.
   - When the composite threat score crosses the escalation threshold, it packages an `IncidentContext` and dispatches it asynchronously to `wt-frontal`.
3. **Deterministic Policy Engine & Ed25519 Signer (`internal/core/policy`):**
   - Acts as the final gatekeeper for every `ActionProposal` returned by `wt-frontal`:
     - **Rule 1 (Whitelist Immunity):** If the target IP or process is whitelisted, the proposal is rejected even if AI confidence is `1.0`.
     - **Rule 2 (Automated Network Defense):** If `Action == BAN_TEMP` or `BAN_PERM` and `Confidence >= 0.85`, Core signs the command payload with its **Ed25519 private key** (`Origin: "CORTEX_SIGNED"`) and pushes it via `CommandStream`.
     - **Rule 3 (Human-in-the-Loop Gate):** If `Action == KILL_PROCESS` or `ISOLATE_HOST`, Core records the proposal in `pending_approvals` and dispatches an interactive `ntfy.sh` notification with **[Approve]** / **[Reject]** webhook buttons. The command is signed and transmitted only upon explicit administrator confirmation.

---

### 3.2 `wt-frontal` (The Frontal Cortex — Isolated AI SOC)

**Binary Name:** `wt-frontal`  
**Design Principle:** Stateless reasoning microservice; zero direct access to the database or agents.

1. **Prompt Injection Sanitizer (`internal/frontal/sanitizer`):**
   - Prevents indirect prompt injection via crafted HTTP headers or log payloads (`Ignore previous instructions...`) by truncating untrusted strings to 256 chars, stripping control/ANSI characters (`\r`, `\n`), and hex-encoding raw telemetry inside `<untrusted_telemetry_hex_encoded>` tags.
2. **Provider-Agnostic OpenAI-Compatible Client (`internal/frontal/llm_client`):**
   - Connects to any OpenAI-compatible API (`OpenRouter`, `AWS Bedrock Gateway`, `Ollama`, `vLLM`, `llama-server`).
   - Enforces grammar/schema constraints (`response_format: json_schema`):
   ```json
   {
     "incident_id": "inc-8821",
     "confidence": 0.94,
     "reasoning": "IP 45.x.x.x triggered 3 SSH failures followed by suspicious curl execution under www-data.",
     "recommended_action": "KILL_PROCESS",
     "target": "pid:4412"
   }
   ```
   - Falls back safely to `recommended_action: "NO_OP"` on timeout (`>15s`) or schema validation failure.

---

### 3.3 `wt-midbrain` (The Midbrain — Threat Intelligence Aggregator, v1.5)

**Binary Name:** `wt-midbrain`  
**Function:** Periodically polls open-source CTI feeds (Abuse.ch Feodo Tracker, MalwareBazaar, ThreatFox), normalizes O(1) lookup indicators (known malicious SHA256 file hashes and C2 IPv4/IPv6 addresses), and distributes compact IOC bundles to agents through `wt-core`.

---

### 3.4 `wt-sentry` (Sensory Nerves)

**Binary Name:** `wt-sentry`  
**Privileges:** Unprivileged user (`watchtower` + `adm` group for log reading). **NEVER runs as root.**  
**Resource Target:** 64MB - 128MB RAM, 0.2 CPU

1. **Sliding-Window LogWatcher (`internal/sentry/logwatcher`):**
   - Monitors `/var/log/auth.log` and web logs via `fsnotify`, handling `logrotate` (`IN_MOVE_SELF`) seamlessly.
   - Suppresses single-match alerts on frequency patterns. When `(RuleName, SourceIP)` crosses threshold within the sliding window (e.g., 3 SSH failures -> `TARPIT`, 5 failures -> `BAN_TEMP`), it triggers the local **Reflex Arc** (`/run/watchtower/turret.sock` with `Origin: "REFLEX"`) and streams telemetry to `wt-core`.
2. **Package-Lock Aware Read-Only FIM & Event-Driven IOC Matcher (`internal/sentry/fim`):**
   - Watches critical paths (`/etc/passwd`, `/bin`, `/usr/bin`, `/tmp`, `/dev/shm`) via `fsnotify`. **Full disk scanning is strictly forbidden.**
   - **Package Manager Lock Check:** Inspects `/var/lib/dpkg/lock-frontend` and `/var/lib/rpm/.rpm.lock`. If locked by an active OS update, FIM downgrades alerts from `L4 Critical` to `L1 Maintenance_Change`.
   - **O(1) IOC Hash Matching:** Computes SHA256 of newly written executables in `<1ms` and checks the in-memory `Midbrain` IOC map. If matched inside `/tmp`, `/var/tmp`, or `/dev/shm`, it triggers a `REFLEX` `KILL_TEMP_MALWARE` request to Turret; if matched in system directories, it emits an `L4 CriticalIOCMatch` to Core without touching the file.
   - **Amygdala Decoy Receptors (Planned v2.0):** Monitors honeypot canary files (e.g., fake `.env` or SSH keys) via `IN_OPEN` for zero-false-positive breach detection.
3. **Shell-Free `/proc` Collector (`internal/sentry/metrics`):**
   - Parses `/proc/stat`, `/proc/meminfo`, `/proc/net/dev`, and `/proc/net/tcp` directly without spawning `ps`, `top`, or `netstat`. Matches active outbound TCP connections against `Midbrain` C2 IPs in O(1) time.

---

### 3.5 `wt-turret` (Motor Nerves & Muscle)

**Binary Name:** `wt-turret`  
**Privileges:** `root` (or `CAP_NET_ADMIN` + `CAP_KILL`)  
**Socket:** `/run/watchtower/turret.sock` (`0660`, `root:watchtower`). Zero network listeners.

1. **Safety Layer (`internal/turret/safety` — Mandatory Pre-Flight Checks):**
   - **Self-Preservation:** Hardcoded immunity for `127.0.0.0/8`, `::1`, local interface IPs, default gateway, configured DNS servers, and WireGuard subnet (`10.8.0.0/24`).
   - **Origin & Cryptographic Policy Enforcement:**
     - `Origin == "REFLEX"` permits ONLY `TARPIT`, `BAN_TEMP` (`TTL <= 900s`), and `KILL_TEMP_MALWARE` (verified via `filepath.Clean` to reside strictly inside `/tmp/`, `/var/tmp/`, or `/dev/shm/`).
     - `BAN_PERM`, `KILL_PROCESS`, and `ISOLATE_HOST` require `Origin == "CORTEX_SIGNED"` and a valid **Ed25519 signature** verified against `/etc/watchtower/core_pub.key`.
   - **Adaptive Subnet Limiter:** Tracks bans per `/24` IPv4 (and `/64` IPv6) prefix in a 60s sliding window. Exceeding 10 bans/min from a single `/24` escalates that `/24` subnet to `wt_temp_ban` while keeping IPS protection active for all other traffic.
2. **Kernel Enforcement (`internal/turret/executor`):**
   - Initializes `ipset` sets: `wt_temp_ban` (`hash:net timeout 300`), `wt_perm_ban` (`hash:net`), and `wt_tarpit` (`hash:ip timeout 60`).
   - Inserts rules at the **top** of the `INPUT` chain (`iptables -I INPUT 1 ...`) above `ESTABLISHED,RELATED`:
     ```bash
     iptables -I INPUT 1 -m set --match-set wt_perm_ban src -j DROP
     iptables -I INPUT 2 -m set --match-set wt_temp_ban src -j DROP
     iptables -I INPUT 3 -m set --match-set wt_tarpit src -m hashlimit --hashlimit-above 1/sec --hashlimit-burst 2 --hashlimit-mode srcip --hashlimit-name wt_tarpit_lim -j DROP
     ```
3. **PID-Reuse Protected Process Termination:**
   - Resolves `/proc/<PID>/exe` immediately prior to sending `syscall.SIGKILL` and verifies it matches `TargetExec`. For `KILL_TEMP_MALWARE`, it strips execution permissions (`chmod 0600`) without deleting the binary to preserve forensic evidence.

---

## 4. Data Management & Database Schema

### 4.1 PostgreSQL 14 + TimescaleDB Schema (`deployments/sql/schema.sql`)

```sql
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- 1. TELEMETRY & SECURITY EVENTS (Hypertable)
CREATE TABLE events (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ NOT NULL,
    agent_id VARCHAR(64) NOT NULL,
    layer VARCHAR(16) NOT NULL,          -- 'L3_NET', 'L7_APP', 'HOST_LOG', 'HOST_FIM', 'HOST_PROC'
    event_type VARCHAR(50) NOT NULL,
    severity SMALLINT NOT NULL,          -- 1 (Low) .. 4 (Critical)
    source_ip INET,
    process_name VARCHAR(128),
    pid INT,
    file_sha256 CHAR(64),
    raw_sanitized TEXT,
    metadata JSONB,
    action_taken VARCHAR(30),
    PRIMARY KEY (timestamp, id)
);

SELECT create_hypertable('events', 'timestamp');
SELECT add_retention_policy('events', INTERVAL '120 days');
SELECT add_compression_policy('events', INTERVAL '7 days');

CREATE INDEX idx_events_agent_time ON events(agent_id, timestamp DESC);
CREATE INDEX idx_events_ip_time ON events(source_ip, timestamp DESC) WHERE source_ip IS NOT NULL;

-- 2. HIPPOCAMPUS SEASONAL BASELINES
CREATE TABLE baselines (
    agent_id VARCHAR(64) NOT NULL,
    metric_name VARCHAR(32) NOT NULL,
    day_of_week SMALLINT NOT NULL,
    hour_of_day SMALLINT NOT NULL,
    avg_value NUMERIC(12,4) NOT NULL,
    stddev_value NUMERIC(12,4) NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (agent_id, metric_name, day_of_week, hour_of_day)
);

-- 3. AGENT FLEET METADATA
CREATE TYPE agent_status AS ENUM ('ALIVE', 'STALE', 'DEAD', 'ISOLATED');

CREATE TABLE agents (
    id VARCHAR(64) PRIMARY KEY,
    hostname VARCHAR(128) NOT NULL,
    ip_address INET NOT NULL,
    version VARCHAR(24) NOT NULL,
    ioc_version BIGINT DEFAULT 0,
    status agent_status DEFAULT 'ALIVE',
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. CERTIFICATES (mTLS - Private Keys are NEVER stored here!)
CREATE TABLE certificates (
    serial_number VARCHAR(64) PRIMARY KEY,
    agent_id VARCHAR(64) UNIQUE NOT NULL REFERENCES agents(id),
    cert_pem TEXT NOT NULL,
    fingerprint_sha256 CHAR(64) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT
);

-- 5. HUMAN-IN-THE-LOOP PENDING APPROVALS
CREATE TABLE pending_approvals (
    incident_id VARCHAR(64) PRIMARY KEY,
    agent_id VARCHAR(64) NOT NULL REFERENCES agents(id),
    proposed_action VARCHAR(32) NOT NULL, -- 'KILL_PROCESS', 'ISOLATE_HOST'
    target VARCHAR(256) NOT NULL,
    target_exec VARCHAR(256),
    confidence NUMERIC(4,3) NOT NULL,
    reasoning TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING', -- 'PENDING', 'APPROVED', 'REJECTED', 'EXPIRED'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    decided_by VARCHAR(64),
    decided_at TIMESTAMPTZ
);

-- 6. MIDBRAIN THREAT INTELLIGENCE INDICATORS (IOCs)
CREATE TABLE ioc_indicators (
    id BIGSERIAL PRIMARY KEY,
    indicator_type VARCHAR(16) NOT NULL,  -- 'SHA256', 'IPV4', 'IPV6', 'DOMAIN'
    value VARCHAR(256) NOT NULL UNIQUE,
    threat_family VARCHAR(64),
    source_feed VARCHAR(64) NOT NULL,
    confidence SMALLINT NOT NULL DEFAULT 80,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

-- 7. APPEND-ONLY AUDIT LOGS (WORM Semantics)
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor VARCHAR(64) NOT NULL,
    action_type VARCHAR(32) NOT NULL,
    target VARCHAR(256),
    reason TEXT,
    prev_hash CHAR(64) NOT NULL,
    entry_hash CHAR(64) NOT NULL
);

-- Security Rule: wt_core DB user only receives INSERT and SELECT privileges on audit_logs!
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM wt_core;
GRANT INSERT, SELECT ON audit_logs TO wt_core;
```

---

## 5. Security, PKI & Trust Boundaries

### 5.1 CSR-Based mTLS Enrollment (Zero Private-Key Exposure)
1. The administrator generates a single-use, 15-minute enrollment token on Core: `wt-cli agent token-create --name web-server-1`.
2. On first boot, `wt-sentry` generates its own Ed25519/ECDSA private key locally at `/etc/watchtower/agent.key` (`0600`).
3. `wt-sentry` creates a Certificate Signing Request (CSR) and invokes the `EnrollAgent` gRPC method with the one-time token. The private key never leaves the agent host.
4. `wt-core` validates the token, signs the CSR using the CA key, stores the public `cert_pem` in PostgreSQL, and returns the signed certificate.

### 5.2 Ed25519 Command Signing (`CORTEX_SIGNED`)
- `wt-core` maintains an offline-backed Ed25519 Command Signing keypair (`core_sign.key` / `core_pub.key`).
- Every conscious response command (`BAN_PERM`, `KILL_PROCESS`, `ISOLATE_HOST`) is canonically serialized (`id|timestamp|agent_id|action|target|target_exec`) and signed by `wt-core`.
- `wt-turret` verifies the Ed25519 signature against `/etc/watchtower/core_pub.key` before executing any `CORTEX_SIGNED` action. Even if an attacker compromises the unprivileged `wt-sentry` user, they cannot forge `CORTEX_SIGNED` commands to kill system processes or isolate the server.

---

## 6. Operational Procedures & CLI (`wt-cli`)

```bash
# 1. Initialize CA and Ed25519 Command Signing Keypair
wt-cli pki init --output /etc/watchtower/pki/

# 2. Interactive Setup Wizard (DB, ntfy.sh, and Optional OpenRouter/Bedrock/Ollama Config)
wt-cli setup-wizard

# 3. Generate One-Time Enrollment Token for a New Agent
wt-cli agent token-create --name web-server-1 --ttl 15m

# 4. Monitor Fleet & Real-Time Synaptic Telemetry
wt-cli agents list
wt-cli events tail --agent web-server-1 --severity 3

# 5. Review and Approve Pending High-Risk Actions (CLI Alternative to ntfy.sh)
wt-cli approvals list
wt-cli approvals approve inc-8821 --reason "Confirmed cryptominer in /tmp"

# 6. Trigger Manual Midbrain IOC Feed Synchronization
wt-cli ioc sync
```

---

## 7. Realistic Development Roadmap

| Phase | Focus Area | Deliverables | Verification Gate |
|-------|------------|--------------|-------------------|
| **Phase 0** | **Synaptic Contract Lock** | `pkg/synapse/xdr.proto`, `pkg/synapse/ipc.go`, `deployments/sql/schema.sql`, `Makefile` | `protoc` generation and `CGO_ENABLED=0 go build ./pkg/...` exit with `0`. |
| **Phase 1** | **`wt-turret` (Safety First)** | `/run/watchtower/turret.sock`, Whitelist, Self-Preservation, Adaptive `/24` Limiter, `ipset`/`iptables` `-I INPUT 1` executor, Ed25519 verifier | `go test -v -race ./internal/turret/...` passes 100% (including localhost self-ban rejection and `REFLEX` path traversal rejection). |
| **Phase 2** | **`wt-sentry` (Sensory & Reflex)** | Sliding-window `fsnotify` LogWatcher, `dpkg`-lock aware read-only FIM, `/proc` collector, O(1) IOC matcher, mTLS gRPC client | False-positive regression corpus (WordPress `.php`, `;` query strings, single SSH typo) and IOC matching unit tests pass. |
| **Phase 3** | **`wt-core` & `Hippocampus`** | CSR enrollment, TimescaleDB writer, `internal/core/hippocampus` cache (`<1ms` Z-Score), 5-min Correlator, Policy Engine, `ntfy.sh` webhook | Unit tests verify unapproved `KILL_PROCESS` proposals are blocked and whitelisted IPs remain untouchable. |
| **Phase 4** | **`wt-frontal` & `wt-cli`** | Prompt Injection Sanitizer, OpenAI/OpenRouter/Ollama client (strict JSON Schema), `wt-cli`, `setup-wizard` | Adversarial Prompt Injection tests and malformed JSON fallback (`NO_OP`) tests pass. |
| **Phase 5** | **`wt-midbrain` (CTI Aggregator)** | Automated Abuse.ch / MalwareBazaar IOC feeds and Amygdala decoy file watcher | `<1ms` lookup benchmark with 100,000 IOCs and CTI feed ingestion unit tests pass. |