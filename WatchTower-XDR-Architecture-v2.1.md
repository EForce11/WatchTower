# 🏛️ WatchTower XDR - System Design Document v2.1 (UNIVERSAL ARCHITECTURE)

**Project Status:** Production-Ready Architecture ✅ | Code: Pre-Release (v0.x.0)  
**Last Updated:** 2026-02-08 (Full English translation, optimized roadmap)  
**Architect & Developer:** Emir Furkan Ulu
**Slogan:** "Enterprise-grade XDR for everyone, everywhere."

---

## 📊 Project Versioning Strategy

**Documentation Version:** v2.1.0 (this document)
- Tracks architectural evolution
- Major version = significant design changes
- Minor version = translations, optimizations, corrections
- Current: v2.1.0 (fully English, optimized)

**Software Version:** v0.1.0-alpha (code in repository)
- Follows semantic versioning
- v0.x.x = pre-release, API unstable
- v1.0.0 = first stable release (production-ready)
- Current status: v0.1.0-alpha (Phase 0 in development)

**Versioning Convention:**
```
v0.1.0 - Architecture design complete, basic protobuf
v0.2.0 - Phase 0 complete (gRPC hello world)
v0.3.0 - Phase 1 complete (LogWatcher + PostgreSQL)
v0.4.0 - Phase 2 complete (Heartbeat + Anomaly)
v0.5.0 - Phase 3 complete (Turret IPS)
v0.6.0 - Phase 4 complete (Anomaly Engine)
v0.9.0 - Phase 6 complete (Interceptor + Installer)
v1.0.0 - First production release 🚀
```

---

## 📋 Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Architecture](#system-architecture)
3. [Component Specifications](#component-specifications)
4. [Data Management](#data-management)
5. [Security & Compliance](#security--compliance)
6. [Operational Procedures](#operational-procedures)
7. [Development Roadmap](#development-roadmap)
8. [Appendices](#appendices)

---

## 1. Executive Summary

### 1.1 Project Vision
> **"Security you can trust... mostly."**  
> WatchTower is a self-hosted, open-source XDR (Extended Detection and Response) suite designed for small-to-medium deployments. Built with the philosophy of "simple setup, minimal maintenance, maximum security."

### 1.2 Core Principles
- **Self-Hosted First:** No cloud dependencies, full data ownership
- **Cloud-Agnostic:** Works on AWS, DigitalOcean, Hetzner, on-premise, or any Linux
- **Modular Architecture:** Each component does ONE thing well
- **Fail-Safe by Design:** Offline resilience, no single point of failure
- **Explainable Security:** Every decision backed by math, not black-box AI
- **Universal Deployment:** From Raspberry Pi to enterprise data centers

### 1.3 Technology Stack (NON-NEGOTIABLE)

| Layer | Technology | Justification |
|-------|------------|---------------|
| **Language** | Go 1.21+ | Single binary, low memory, native concurrency |
| **IPC** | gRPC + Protobuf | Fast, type-safe, supports streaming |
| **Local IPC** | Unix Domain Sockets | Zero network overhead, kernel-level security |
| **Database** | PostgreSQL 14+ | ACID compliance, mature, reliable |
| **Time-Series** | TimescaleDB | Native PostgreSQL extension, no extra daemon |
| **Notifications** | ntfy.sh | Self-hostable, HTTP-based push notifications |
| **Dashboard** | Grafana 10+ | TimescaleDB plugin, zero custom UI code |
| **VPN** | WireGuard | Modern, fast, kernel-integrated |

**See Section 8.6 for detailed technology decision rationale.**

### 1.4 Deployment Scope

**Universal Compatibility:**
- ✅ **Cloud Providers:** AWS EC2, DigitalOcean, Hetzner, Linode, Vultr, OVH
- ✅ **On-Premise:** Physical servers, Proxmox, VMware ESXi, Hyper-V
- ✅ **Hybrid:** Mix of cloud + on-prem (common for SMBs)
- ✅ **Edge:** Raspberry Pi, ARM servers, IoT gateways
- ✅ **Containers:** Docker, Kubernetes (agents as sidecars)

**Example Deployments:**

**Scenario 1: Startup (3 servers)**
```
Core:    AWS t3.small (us-east-1) - 2GB RAM, 20GB SSD
Web:     DigitalOcean Droplet (nyc3) - WordPress + Sentry + Interceptor
DB:      Hetzner CX21 (Germany) - PostgreSQL + Sentry
```

**Scenario 2: SMB (10 servers)**
```
Core:       Dedicated VPS (OVH) - 4GB RAM, 50GB SSD
5x Web:     AWS + Cloudflare origin - Nginx + Sentry + Interceptor
2x DB:      MySQL primary/replica - Sentry only
2x Internal: Redis, RabbitMQ - Sentry + Turret
1x Storage: Nextcloud - Sentry + FIM
```

**Scenario 3: Self-Hosted Enthusiast**
```
Core:    Home server (Raspberry Pi 4 or mini PC) - Behind VPN
Agents:  Cheap VPS'ler (Contabo €4/mo, Scaleway) - Public services
         Home servers - Internal services
```

**Scenario 4: Enterprise (100+ servers)**
```
Core:       HA cluster (3 nodes) - On-premise
Agents:     Mixed cloud (AWS + Azure + GCP) - Multi-region
Dashboard:  Grafana Cloud - Centralized monitoring
```

**Design Capacity:**
- Small: 1-10 agents (tested on Raspberry Pi 4)
- Medium: 10-100 agents (single Core server)
- Large: 100-1000 agents (HA Core cluster)
- Enterprise: 1000+ agents (distributed Core architecture)

---

## 2. System Architecture

### 2.1 High-Level Topology

```
┌─────────────────────────────────────────────────────────────┐
│                         INTERNET                            │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ HTTPS/SSH (Standard Ports)
                         │
          ┌──────────────▼───────────────┐
          │    Oracle Cloud Always Free  │
          │                              │
          │  ┌────────────────────────┐  │
          │  │   Vaultwarden Server   │  │
          │  │                        │  │
          │  │  ┌──────────────────┐  │  │
          │  │  │   Nginx          │  │  │  ◄─┐
          │  │  │   (SSL Term.)    │  │  │    │
          │  │  └────────┬─────────┘  │  │    │
          │  │           │             │  │    │
          │  │  ┌────────▼─────────┐  │  │    │
          │  │  │ WT-Interceptor   │  │  │    │ gRPC/mTLS
          │  │  │ (L7 WAF)         │  │  │    │ Port 50051
          │  │  └────────┬─────────┘  │  │    │
          │  │           │             │  │    │
          │  │  ┌────────▼─────────┐  │  │    │
          │  │  │   Vaultwarden    │  │  │    │
          │  │  │   (Application)  │  │  │    │
          │  │  └──────────────────┘  │  │    │
          │  │                        │  │    │
          │  │  ┌──────────────────┐  │  │    │
          │  │  │   WT-Sentry      │  │  │  ◄─┤
          │  │  │   (HIDS - RO)    │  │  │    │
          │  │  └────────┬─────────┘  │  │    │
          │  │           │ Unix Socket│  │    │
          │  │  ┌────────▼─────────┐  │  │    │
          │  │  │   WT-Turret      │  │  │    │
          │  │  │   (IPS - Root)   │  │  │    │
          │  │  └──────────────────┘  │  │    │
          │  └────────────────────────┘  │    │
          │                              │    │
          │  ┌────────────────────────┐  │    │
          │  │     Blog Server        │  │    │
          │  │  ┌──────────────────┐  │  │    │
          │  │  │   Nginx          │  │  │    │
          │  │  └────────┬─────────┘  │  │    │
          │  │  ┌────────▼─────────┐  │  │    │
          │  │  │ WT-Interceptor   │  │  │  ◄─┤
          │  │  └────────┬─────────┘  │  │    │
          │  │  ┌────────▼─────────┐  │  │    │
          │  │  │   Blog App       │  │  │    │
          │  │  └──────────────────┘  │  │    │
          │  │  ┌──────────────────┐  │  │    │
          │  │  │   WT-Sentry      │  │  │  ◄─┤
          │  │  └────────┬─────────┘  │  │    │
          │  │           │ Unix Socket│  │    │
          │  │  ┌────────▼─────────┐  │  │    │
          │  │  │   WT-Turret      │  │  │    │
          │  │  └──────────────────┘  │  │    │
          │  └────────────────────────┘  │    │
          └──────────────────────────────┘    │
                                              │
                         ┌────────────────────┘
                         │
          ┌──────────────▼───────────────────────────┐
          │      Management Network (Isolated)       │
          │      (Different VPS or VLAN)             │
          │                                          │
          │  ┌────────────────────────────────────┐  │
          │  │         WT-Core (Primary)          │  │
          │  │  ┌──────────────────────────────┐  │  │
          │  │  │  gRPC Server (50051)         │  │  │
          │  │  │  - Agent Auth (mTLS)         │  │  │
          │  │  │  - Heartbeat Receiver        │  │  │
          │  │  │  - Alert Ingestion (L3-L7)   │  │  │
          │  │  │  - Config Distributor        │  │  │
          │  │  │  - Installer Generator       │  │  │
          │  │  └──────────────────────────────┘  │  │
          │  │  ┌──────────────────────────────┐  │  │
          │  │  │  Anomaly Engine              │  │  │
          │  │  │  - Statistical Profiler      │  │  │
          │  │  │  - Correlation Engine        │  │  │
          │  │  │  - Baseline Calculator       │  │  │
          │  │  └──────────────────────────────┘  │  │
          │  │  ┌──────────────────────────────┐  │  │
          │  │  │  Fleet Manager               │  │  │
          │  │  │  - Config Versioning         │  │  │
          │  │  │  - Update Orchestrator       │  │  │
          │  │  │  - Health Monitor             │  │  │
          │  │  └──────────────────────────────┘  │  │
          │  └────────────┬─────────────────────┘  │
          │               │                        │
          │  ┌────────────▼─────────────────────┐  │
          │  │  PostgreSQL 14 + TimescaleDB     │  │
          │  │  - Events (L3/L4/L7 - Hypertable)│  │
          │  │  - Baselines (Seasonal)          │  │
          │  │  - Audit Logs (Append-Only)      │  │
          │  │  - Agent Metadata                │  │
          │  └──────────────────────────────────┘  │
          │                                        │
          │  ┌────────────────────────────────────┐│
          │  │     Grafana Dashboard (8080)       ││
          │  │     - Real-time Event Stream       ││
          │  │     - DEFCON Status Board          ││
          │  │     - L7 Attack Visualization      ││
          │  │     - Baseline Visualization       ││
          │  └────────────────────────────────────┘│
          │                                        │
          │  ┌────────────────────────────────────┐│
          │  │  WT-Core (Standby)                 ││
          │  │  - Monitors Primary Heartbeat      ││
          │  │  - Promotes on timeout (90s)       ││
          │  └────────────────────────────────────┘│
          └────────────────────────────────────────┘
                         ▲
                         │ WireGuard VPN
                         │ (10.8.0.0/24)
                         │
          ┌──────────────┴─────────────────┐
          │      Admin Laptop              │
          │  - SSH Access (Core)           │
          │  - Grafana (Browser)           │
          │  - wt-cli (Management Tool)    │
          │  - Installer Generation        │
          └────────────────────────────────┘
```

**Defense-in-Depth (Multi-Layer Protection):**
```
Layer 7 (Application):   WT-Interceptor → SQLi, XSS, rate limiting
Layer 4 (Transport):     Turret → IP blocking, connection filtering  
Layer 3 (Network):       WT-Guard (Future) → Packet analysis
```

### 2.2 Component Communication Matrix

| Source | Destination | Protocol | Port | Auth | Purpose |
|--------|-------------|----------|------|------|---------|
| Sentry | Turret | Unix Socket | - | File permissions | Command execution |
| Sentry | Core | gRPC/TLS | 50051 | mTLS + Token | Event reporting (L3/L4) |
| Sentry | Interceptor | Unix Socket | - | File permissions | L7 threat sharing |
| Interceptor | Core | gRPC/TLS | 50051 | mTLS + Token | L7 threat reporting |
| Interceptor | Application | HTTP | varies | None | Reverse proxy |
| Nginx | Interceptor | HTTP | 8081 | None (localhost) | Request forwarding |
| Turret | Core | - | - | - | None (passive) |
| Core | Agents | gRPC/TLS | - | mTLS | Config push |
| Admin | Core | SSH | 22 | WireGuard + pubkey | Management |
| Admin | Grafana | HTTPS | 8080 | WireGuard + BasicAuth | Monitoring |
| Core-Primary | Core-Standby | gRPC | 50052 | mTLS | Heartbeat |

### 2.3 Trust Boundaries

```
┌──────────────────────────────────────────────┐
│           UNTRUSTED ZONE                     │
│  - Internet traffic                          │
│  - Attacker-controlled inputs                │
└──────────────┬───────────────────────────────┘
               │
        ┌──────▼──────┐
        │  Firewall   │ ◄─── First Defense
        └──────┬──────┘
               │
┌──────────────▼───────────────────────────────┐
│           SEMI-TRUSTED ZONE (DMZ)            │
│  - Public-facing services                    │
│  - Sentry (Read-Only monitoring)             │
│  - Turret (Root but command-driven only)     │
│                                              │
│  Threat: Compromised application             │
│  Mitigation: mTLS cert revocation, Turret    │
│              whitelist, Core validation      │
└──────────────┬───────────────────────────────┘
               │ gRPC/mTLS
               │ (Agent can only SEND, not receive)
               │
┌──────────────▼───────────────────────────────┐
│           TRUSTED ZONE                       │
│  - Core (The Brain)                          │
│  - Database (PostgreSQL)                     │
│  - Grafana Dashboard                         │
│                                              │
│  Access: VPN-only (Admin laptop)             │
│  Threat: Insider, stolen laptop              │
│  Mitigation: 2FA (future), SSH key rotation  │
└──────────────────────────────────────────────┘
```

---

## 3. Component Specifications

### 3.1 WT-Core (The Brain)

**Binary Name:** `wt-core`  
**Deployment:** Systemd service on isolated server  
**Resources:** 2GB RAM, 2 CPU cores, 20GB SSD  

#### 3.1.1 Modules

**A. gRPC Server**
```
Port: 50051 (TLS)
Services:
  - AgentRegistration: Initial handshake, cert validation
  - Heartbeat: 30s interval, config sync
  - AlertIngestion: Real-time event push from Sentries
  - ResponseControl: Send commands (UNBAN, CONFIG_UPDATE)
  
Rate Limiting: 100 requests/sec per agent
Connection Pool: Max 50 agents (configurable)
Timeout: 30s for blocking calls
```

**B. Anomaly Engine**
```
Input: Metrics from Heartbeat + Events
Processing:
  1. Fetch baseline from TimescaleDB
     Query: SELECT avg, stddev WHERE agent_id=X AND dow=Y AND hour=Z
  
  2. Calculate Z-Score:
     z = (current_value - baseline_avg) / baseline_stddev
  
  3. Correlation Check:
     - If CPU spike + Disk spike → Deployment (L1)
     - If Network spike alone → Attack (L3)
     - If Egress spike + New process → Exfiltration (L4)
  
  4. Emit DEFCON level
  
Output: Threat score (0-300), DEFCON level (L1-L4)
Performance: <10ms per metric evaluation
```

**C. Fleet Manager**
```
Responsibilities:
  - Agent health tracking (heartbeat timeout: 90s)
  - Config versioning (SHA256 hash tracking)
  - Update orchestration (binary distribution)
  - Certificate lifecycle (issue, renew, revoke)
  
Database Tables:
  - agents (id, hostname, last_seen, config_hash, status)
  - config_versions (version, hash, deployed_at, changelog)
  - certificates (agent_id, cert_pem, expires_at, revoked)
```

**D. Update Orchestrator** ⭐
```
Function: Core-Driven Agent Updates

Workflow:
  1. Admin uploads new binary to Core:
     PUT /api/v1/updates/upload
     Body: {version: "v1.2.0", binary: <multipart/form-data>}
  
  2. Core validates:
     - SHA256 checksum match
     - GPG signature (optional future)
     - Version semver format
  
  3. Core stores in: /var/lib/watchtower/updates/v1.2.0/
  
  4. Admin triggers rollout:
     POST /api/v1/updates/rollout
     Body: {
       version: "v1.2.0",
       targets: ["web-server-1", "blog-server-1"],
       strategy: "rolling",
       rollback_on_error: true
     }
  
  5. Core sends gRPC to agents:
     UpdateAvailable {
       version: "v1.2.0",
       download_url: "grpc://core.internal/updates/v1.2.0",
       checksum: "abc123...",
       restart_required: true
     }
  
  6. Agent downloads via gRPC stream:
     - Downloads to /tmp/wt-sentry-v1.2.0
     - Verifies SHA256
     - Atomically replaces: mv /tmp/wt-sentry-v1.2.0 /usr/local/bin/wt-sentry
     - Runs: systemctl restart wt-sentry
  
  7. Agent reports back:
     UpdateComplete {
       version: "v1.2.0",
       status: "SUCCESS",
       uptime: 5s
     }
  
  8. Core tracks rollout progress:
     - 2/2 agents updated → Rollout complete
     - If any agent fails → Auto-rollback (sends previous version)

Rollback Scenario:
  - Agent crashes after update
  - Heartbeat timeout (90s)
  - Core detects: "Agent updated to v1.2.0 but died"
  - Core broadcasts: "All agents, rollback to v1.1.9"
  - Audit log: "Auto-rollback triggered - v1.2.0 deemed unstable"
```

**E. Baseline Cache Layer** ⭐ NEW (v1.1)
```
Function: In-Memory Caching to Prevent DB Bottleneck

Problem (v1.0):
  - 100 events/sec = 100 SQL queries/sec to fetch baselines
  - PostgreSQL becomes bottleneck under load
  
Solution:
  - Load baselines into RAM (Go map)
  - Z-Score calculation happens in-memory (<1ms)
  - Background refresh every 10 minutes
  
Architecture:
  ┌─────────────────────────────────────┐
  │   Baseline Cache (In-Memory)       │
  │   map[string]*Baseline              │
  │   Key: "agent:metric:dow:hour"     │
  │   Value: {avg, stddev, updated_at} │
  │   Size: ~10,000 entries (~50MB)    │
  └──────────┬──────────────────────────┘
             │ Read (<1ms)
             │
  ┌──────────▼──────────┐
  │  Z-Score Calculator │
  │  (RAM-based)        │
  └─────────────────────┘
             ▲
             │ Refresh (every 10 min)
             │
  ┌──────────┴──────────┐
  │  PostgreSQL/        │
  │  TimescaleDB        │
  └─────────────────────┘

Implementation:
  type BaselineCache struct {
      data   map[string]*Baseline
      mutex  sync.RWMutex
      db     *sql.DB
      ttl    time.Duration
  }
  
  func (c *BaselineCache) Get(agent, metric string, dow, hour int) *Baseline {
      key := fmt.Sprintf("%s:%s:%d:%d", agent, metric, dow, hour)
      
      c.mutex.RLock()
      baseline, exists := c.data[key]
      c.mutex.RUnlock()
      
      // Cache hit (90%+ of cases)
      if exists && time.Since(baseline.UpdatedAt) < c.ttl {
          return baseline
      }
      
      // Cache miss - fetch from DB and update
      return c.fetchAndCache(key, agent, metric, dow, hour)
  }
  
Configuration:
  anomaly:
    cache:
      enabled: true
      ttl: "10m"
      preload_on_startup: true
      max_entries: 10000
      
Performance Impact:
  - Without cache: 100 events/sec → 100 DB queries/sec → PostgreSQL overload
  - With cache: 100 events/sec → 0 DB queries/sec → Z-Score in <1ms
  - Memory usage: ~50MB for 10,000 baselines
  - Cache hit rate: >95% (after warm-up)
```

**F. ML-Ready Architecture (Strategy Pattern)** ⭐ NEW (v2.0)
```
Purpose: Swap anomaly detection algorithms like changing a car's air filter

Current: Statistical (Z-Score)
Future:  Machine Learning (PyTorch, TensorFlow, ONNX)

Design Pattern: Strategy (Pluggable Implementations)

┌─────────────────────────────────────────────────┐
│        Core (Anomaly Detection Client)          │
│                                                  │
│  analyzer := NewAnalyzer(config.Engine)         │
│  threat := analyzer.CalculateThreat(metrics)    │
└──────────────────┬──────────────────────────────┘
                   │ Interface (abstraction)
                   │
    ┌──────────────▼────────────────┐
    │   Analyzer Interface          │
    │   CalculateThreat(Metrics)    │
    │   Train(Dataset)              │
    │   UpdateModel(Path)           │
    └──────────────┬────────────────┘
                   │
        ┌──────────┴──────────┐
        │                     │
┌───────▼────────┐  ┌────────▼────────┐
│ Statistical    │  │  ML Analyzer    │
│ Analyzer       │  │  (PyTorch)      │
│                │  │                 │
│ Z-Score        │  │ LSTM Model      │
│ Seasonality    │  │ GPU/CPU         │
│ EMA Update     │  │ Batch Inference │
└────────────────┘  └─────────────────┘

Implementation (Go):

// Analyzer interface (internal/analysis/analyzer.go)
type Analyzer interface {
    CalculateThreat(ctx context.Context, metrics Metrics) (ThreatScore, error)
    Train(ctx context.Context, dataset []Metrics) error
    UpdateModel(modelPath string) error
}

// Statistical implementation (current - v0.x)
type StatisticalAnalyzer struct {
    cache *BaselineCache
}

func (s *StatisticalAnalyzer) CalculateThreat(ctx context.Context, m Metrics) (ThreatScore, error) {
    baseline := s.cache.Get(m.AgentID, m.Metric, m.DOW, m.Hour)
    zScore := (m.Value - baseline.Avg) / baseline.Stddev
    
    return ThreatScore{
        Score:      int(zScore * 10),
        Method:     "ZScore",
        Confidence: calculateConfidence(zScore),
    }, nil
}

// ML implementation (future - v2.x)
type MLAnalyzer struct {
    model     *pytorch.Model  // or tensorflow.Model, onnx.Model
    threshold float64
    device    string          // "cpu" or "cuda"
}

func (ml *MLAnalyzer) CalculateThreat(ctx context.Context, m Metrics) (ThreatScore, error) {
    // 1. Prepare features (normalize, encode)
    features := ml.prepareFeatures(m)
    
    // 2. Run inference (GPU accelerated if available)
    prediction := ml.model.Predict(features)
    
    // 3. Convert to threat score
    return ThreatScore{
        Score:      int(prediction * 100),
        Method:     "PyTorch-LSTM",
        Confidence: prediction,
    }, nil
}

func (ml *MLAnalyzer) Train(ctx context.Context, dataset []Metrics) error {
    // Training logic (can be offline or online)
    return ml.model.Train(dataset, epochs=100, batchSize=32)
}

Configuration (YAML):

anomaly:
  engine: "statistical"  # or "ml-pytorch", "ml-tensorflow", "ml-onnx"
  
  statistical:
    cache_ttl: "10m"
    z_score_threshold: 3.0
    seasonality_enabled: true
  
  ml_pytorch:
    model_path: "/var/lib/watchtower/models/lstm-v1.pth"
    inference_device: "cpu"  # or "cuda" (GPU)
    threshold: 0.75
    batch_size: 32
    features: ["cpu", "memory", "network_rx", "network_tx", "disk_io"]
  
  ml_tensorflow:
    model_path: "/var/lib/watchtower/models/cnn-v1.pb"
    inference_device: "cpu"
    threshold: 0.80

Factory Pattern (main.go):

func NewAnalyzer(config Config) Analyzer {
    switch config.Anomaly.Engine {
    case "statistical":
        return &StatisticalAnalyzer{cache: loadCache()}
    case "ml-pytorch":
        return &MLAnalyzer{
            model:     loadPyTorchModel(config.ML.ModelPath),
            threshold: config.ML.Threshold,
            device:    config.ML.Device,
        }
    case "ml-tensorflow":
        return &MLTensorFlowAnalyzer{...}
    default:
        log.Fatal("Unknown engine:", config.Anomaly.Engine)
    }
}

// Usage (transparent to Core!)
analyzer := NewAnalyzer(config)
threat := analyzer.CalculateThreat(ctx, metrics)

Data Export for ML Training:

-- Export training dataset (SQL)
COPY (
    SELECT 
        agent_id,
        EXTRACT(DOW FROM timestamp) as day_of_week,
        EXTRACT(HOUR FROM timestamp) as hour,
        EXTRACT(EPOCH FROM timestamp) as unix_time,
        metadata->>'cpu' as cpu,
        metadata->>'memory' as memory,
        metadata->>'network_rx' as network_rx,
        metadata->>'network_tx' as network_tx,
        metadata->>'disk_io' as disk_io,
        severity  -- Label (0=normal, 1-4=threat)
    FROM events
    WHERE timestamp > NOW() - INTERVAL '90 days'
) TO '/tmp/training_data.csv' CSV HEADER;

Offline Training (Python):

# scripts/train_model.py
import pandas as pd
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler

# Load data
df = pd.read_csv('/tmp/training_data.csv')

# Define LSTM model
class ThreatDetectorLSTM(nn.Module):
    def __init__(self, input_size=5, hidden_size=128, num_layers=2):
        super().__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_size, 1)
        self.sigmoid = nn.Sigmoid()
    
    def forward(self, x):
        lstm_out, _ = self.lstm(x)
        output = self.fc(lstm_out[:, -1, :])
        return self.sigmoid(output)

# Train model
model = ThreatDetectorLSTM()
model.train(df, epochs=100)
torch.save(model.state_dict(), '/var/lib/watchtower/models/lstm-v1.pth')

# Deploy to Core
scp /var/lib/watchtower/models/lstm-v1.pth core:/var/lib/watchtower/models/

Benefits:
✅ "Polish filtresi gibi" değiştirilebilir
✅ Kod değişikliği YOK (sadece config)
✅ A/B testing kolay (iki analyzer yan yana çalıştır)
✅ Backward compatible (ML yoksa statistical fall back)
```

#### 3.1.2 Configuration Example

```yaml
# /etc/watchtower/core.yaml
server:
  listen_addr: "0.0.0.0:50051"
  tls:
    ca_cert: "/etc/watchtower/ca.crt"
    server_cert: "/etc/watchtower/core.crt"
    server_key: "/etc/watchtower/core.key"
  
database:
  host: "localhost"
  port: 5432
  name: "watchtower"
  user: "wt_core"
  password_file: "/etc/watchtower/db_password"
  max_connections: 20
  
anomaly:
  baseline_window: "7d"
  update_schedule: "0 3 * * *"
  z_score_threshold:
    L1: 2.0
    L2: 3.0
    L3: 4.0
    L4: 5.0
  cache:                      # ⭐ NEW (v1.1)
    enabled: true
    ttl: "10m"                # Cache refresh interval
    preload_on_startup: true  # Load all baselines on Core start
    max_entries: 10000        # ~50MB RAM
    background_refresh: "10m" # Refresh active baselines every 10 min
  
notifications:
  ntfy_url: "https://ntfy.sh/watchtower-alerts"
  levels:
    L1: false
    L2: true
    L3: true
    L4: true
  
fleet:
  heartbeat_timeout: 90s
  stale_threshold: 90s
  dead_threshold: 180s
  
updates:
  storage_path: "/var/lib/watchtower/updates"
  max_rollout_time: 600s
```

---

### 3.2 WT-Sentry (The Eye)

**Binary Name:** `wt-sentry`  
**Deployment:** Systemd service on each protected server  
**Privileges:** Standard user (NOT root)  
**Resources:** 128MB RAM, 0.5 CPU  

#### 3.2.1 Modules

**A. Log Watcher**
```
Mechanism: fsnotify (inotify on Linux)
Watched Files:
  - /var/log/auth.log (SSH, sudo)
  - /var/log/nginx/access.log (Web attacks)
  - /var/log/syslog (System events)
  
Pattern Matching (Regex):
  - SSH Brute Force: "Failed password for .* from (\\S+)"
  - SQL Injection: "(union.*select|; drop table)"
  - Path Traversal: "\\.\\./"
  
Ring Buffer:
  - Size: 1000 events (circular)
  - Purpose: Offline tolerance (Core down for <60s)
  - Flush: On reconnect or every 30s (batch upload)
```

**B. File Integrity Monitor (FIM)**
```
Mechanism: inotify (IN_CLOSE_WRITE, IN_MOVED_TO)
Watched Paths:
  - /etc/passwd, /etc/shadow
  - /bin, /usr/bin, /sbin (binary directories)
  - /etc/systemd/system/*.service
  - Custom: /opt/vaultwarden/data
  
Baseline:
  - On first run: SHA256 hash all files
  - Store in: /var/lib/watchtower/fim_baseline.db (SQLite)
  
On Change:
  1. Detect: File X modified
  2. Hash: Calculate new SHA256
  3. Compare: Hash mismatch?
  4. Alert: L4 (Critical) → Core + Turret (quarantine)
```

**C. Resource Monitor**
```
Metrics (every 30s):
  - CPU: /proc/stat (user + system time)
  - Memory: /proc/meminfo (MemAvailable)
  - Disk I/O: /proc/diskstats (reads/writes)
  - Network: /proc/net/dev (rx/tx bytes)
  - Load Average: /proc/loadavg
  
Batch Upload:
  - Accumulate 10 samples (5 minutes)
  - Compress (gzip)
  - Send to Core in single gRPC call
```

**D. IPC Client (Turret Commander)**
```
Socket: /tmp/wt/wt-turret.sock
Protocol: JSON over Unix Socket

Message Format:
{
  "id": "uuid-v4",
  "timestamp": "2026-02-08T14:30:00Z",
  "action": "BAN" | "UNBAN" | "KILL" | "QUARANTINE",
  "target": "1.2.3.4" | "pid:4455" | "/tmp/malware.sh",
  "level": 1-4,
  "reason": "SSH brute force - 50 attempts",
  "snapshot": {
    "cpu": 45.2,
    "network_conns": 120
  }
}

Timeout: 5s (if Turret doesn't ACK, log locally and continue)
```

**E. Heartbeat Transmitter**
```
Interval: 30s (configurable)
Payload:
{
  "agent_id": "web-server-1",
  "timestamp": "2026-02-08T14:30:00Z",
  "status": "ALIVE",
  "config_hash": "abc123...",
  "version": "v1.0.0",
  "metrics": {
    "cpu_avg": 23.5,
    "memory_free": 1234567890,
    "events_buffered": 0
  },
  "last_action": {
    "type": "BAN",
    "target": "1.2.3.4",
    "timestamp": "2026-02-08T14:29:45Z"
  }
}
```

#### 3.2.2 Configuration Example

```yaml
# /etc/watchtower/sentry.yaml
agent:
  id: "web-server-1"
  server_url: "core.internal:50051"
  tls:
    cert: "/etc/watchtower/agent.crt"
    key: "/etc/watchtower/agent.key"
    ca: "/etc/watchtower/ca.crt"
  
logs:
  watch_paths:
    - /var/log/auth.log
    - /var/log/nginx/access.log
  patterns:
    - name: "SSH Brute Force"
      regex: "Failed password for .* from (\\S+)"
      threshold: 5
      window: 60s
      action: "BAN"
      level: 3
      pre_action:             # ⭐ NEW (v1.1): Pre-Emptive Throttling
        enabled: true
        threshold: 3          # After 3 failed attempts (before full ban)
        action: "TARPIT"      # Rate limit instead of full ban
        duration: 30s         # Slow down for 30 seconds
  
fim:
  enabled: true
  watch_paths:
    - /etc/passwd
    - /etc/shadow
    - /bin
    - /opt/vaultwarden/data
  exclude:
    - "*.log"
    - "*.tmp"
  
resources:
  interval: 30s
  batch_size: 10
  
heartbeat:
  interval: 30s
  timeout: 10s
  
turret:
  socket: "/tmp/wt/wt-turret.sock"
  timeout: 5s
```

---

### 3.3 WT-Turret (The Fist)

**Binary Name:** `wt-turret`  
**Deployment:** Systemd service (root privileges)  
**Privileges:** CAP_NET_ADMIN (iptables), root (kill, file ops)  
**Resources:** 64MB RAM, 0.1 CPU (idle)  

#### 3.3.1 Action Executor

```
Supported Actions:

1. TARPIT (L2 - Pre-Emptive) ⭐ NEW (v1.1)
   - Purpose: Slow down suspicious IPs before full ban
   - Method: iptables rate limiting
   - Command: iptables -A INPUT -s <IP> -j ACCEPT -m limit --limit 1/sec --limit-burst 2
   - Effect: IP can only send 1 packet/sec (normal: 1000+/sec)
   - Duration: 30 seconds (configurable)
   - Use case: After 3 failed SSH attempts, before reaching ban threshold (5)

2. BAN (L2/L3/L4)
   - L2 (Temporary): ipset add temp_ban <IP> timeout 300
   - L3 (Standard): ipset add perm_ban <IP>
   - L4 (Permanent): ipset add perm_ban <IP> + iptables -j REJECT --reject-with icmp-host-prohibited
   
   ⭐ ipset Optimization (v1.1):
     Instead of adding individual iptables rules per IP (slow):
       OLD: iptables -A INPUT -s 1.2.3.4 -j DROP  (20ms per rule)
       NEW: ipset add perm_ban 1.2.3.4            (<5ms)
     
     Setup (on Turret startup):
       ipset create temp_ban hash:ip timeout 300  # Auto-expire after 5 min
       ipset create perm_ban hash:ip              # Permanent (until reboot)
       iptables -A INPUT -m set --match-set temp_ban src -j DROP
       iptables -A INPUT -m set --match-set perm_ban src -j DROP
     
     Performance:
       - Single iptables rule checks entire ipset (O(1) lookup)
       - Can handle 10,000+ banned IPs without performance degradation
       - Ban latency: <5ms (vs 20ms with individual rules)
   
3. UNBAN
   - Remove from ipset: ipset del temp_ban <IP> || ipset del perm_ban <IP>
   - Remove TARPIT rule: iptables -D INPUT -s <IP> -m limit ...
   
4. KILL
   - Process termination: kill -9 <PID>
   - Validation: Check if process still running after 1s
   
5. QUARANTINE
   - Move file: mv <path> /var/lib/watchtower/quarantine/$(date +%s)_$(basename <path>)
   - Set immutable: chattr +i /var/lib/watchtower/quarantine/*
   - Log hash: sha256sum >> quarantine.log
```

#### 3.3.2 Safety Layer

```
Pre-Flight Checks (EVERY action):

1. Whitelist Validation
   Source: /etc/watchtower/whitelist.yaml
   Check: Is target IP/PID in permanent whitelist?
   Result: ABORT if true, log "Whitelist protection triggered"

2. Self-Preservation
   Hardcoded IPs:
     - 127.0.0.0/8 (localhost)
     - ::1 (IPv6 localhost)
     - <VPN subnet> (from config)
   Result: ABORT + CRITICAL log if attempted

3. Rate Limiter
   Algorithm: Token Bucket
   Capacity: 10 bans per minute
   Refill: 1 token every 6 seconds
   Result: THROTTLE if bucket empty, enter circuit breaker

4. Duplicate Detection
   Cache: Last 100 actions (in-memory)
   Check: Same IP banned in last 5 minutes?
   Result: SKIP (idempotent), log "Duplicate ban attempt"

5. Audit Trail
   Every action logged to:
     - Local: /var/log/watchtower/turret.log
     - Remote: Send to Core via gRPC (async)

6. Pre-Emptive Throttling (Race Condition Mitigation) ⭐ NEW (v1.1)
   Purpose: Slow down attacks before reaching full ban threshold
   Mechanism:
     - After 3 suspicious events (e.g., failed logins)
     - Apply TARPIT (rate limit to 1 packet/sec)
     - Duration: 30 seconds
     - If pattern continues → escalate to full BAN (L3)
   
   Latency Analysis (Detection → Action):
     1. Log written               → 0-10ms
     2. fsnotify event            → 1-5ms
     3. Regex match               → 1-10ms
     4. IPC (Unix Socket)         → <1ms
     5. Safety checks             → 1-5ms
     6. ipset command             → 5ms (optimized)
     ─────────────────────────────────────
     TOTAL (Worst Case):          ~30ms
   
   Attack Window: 30ms = 0.03 seconds
     - SSH brute force: ~1-2 extra attempts (acceptable)
     - DDoS: ~30-150 packets (TARPIT prevents amplification)
     - SQL Injection: Usually single-request (if successful)
   
   Mitigation: Pre-emptive throttling at attempt #3 gives us early warning
                while preserving false-positive tolerance.
   
   Acceptable Risk: For a HIDS, 30ms latency is industry-standard.
                    eBPF would reduce to <1ms but adds complexity (v2.0).
```

#### 3.3.3 Circuit Breaker

```
Trigger Conditions:
  - Rate limit exceeded (>10 bans/min)
  - Disk usage >90%
  - >100 events in ring buffer

States:
  CLOSED → OPEN → HALF-OPEN → CLOSED
  
On OPEN:
  1. Stop executing BAN actions
  2. Switch to LOG_ONLY mode
  3. Send to Core: "Circuit breaker OPEN"
  4. Wait 300s (cooldown)

Recovery:
  - Admin can force reset: wt-cli turret reset-circuit --agent web-server-1
```

#### 3.3.4 Configuration Example

```yaml
# /etc/watchtower/turret.yaml
server:
  socket: "/tmp/wt/wt-turret.sock"
  socket_permissions: "0600"
  
whitelist:
  file: "/etc/watchtower/whitelist.yaml"
  reload_interval: 60s
  
safety:
  rate_limit:
    max_per_minute: 10
    bucket_size: 10
  circuit_breaker:
    enabled: true
    threshold: 100
    cooldown: 300s
  self_preservation:
    vpn_subnet: "10.8.0.0/24"
    admin_ips:
      - "203.0.113.50"
  
actions:
  ban:
    L2_timeout: 300s
    L3_persistent: true
    L4_reject_type: "icmp-host-prohibited"
  quarantine:
    path: "/var/lib/watchtower/quarantine"
    max_size: "1GB"
  
audit:
  log_file: "/var/log/watchtower/turret.log"
  send_to_core: true
```

---

### 3.4 WT-Interceptor (The Gatekeeper) ⭐ NEW (v1.2)

**Binary Name:** `wt-interceptor`  
**Deployment:** Reverse proxy (Hybrid mode: behind Nginx | Standalone mode: replaces Nginx)  
**Privileges:** Standard user (NOT root)  
**Resources:** 128MB RAM, 0.5 CPU  

#### 3.4.1 Purpose

Application-layer (L7) threat detection and prevention. Provides WAF functionality without dependency on external services (Cloudflare, AWS WAF). Ensures continuous protection even when third-party services are unavailable.

**Key Insight:** Most attacks today target the application layer (SQL injection, XSS, brute force on login pages). Turret blocks at L3/L4 (IP level), but Interceptor analyzes HTTP requests before they reach your application.

#### 3.4.2 Deployment Modes

**A. Hybrid Mode (Recommended) ⭐**
```
Internet → Nginx (SSL) → WT-Interceptor (WAF) → Application
          (Port 443)     (Port 8081)            (Port 8080)
```

**Advantages:**
- ✅ Nginx handles SSL/TLS (Let's Encrypt integration easy)
- ✅ Static files served directly by Nginx (fast)
- ✅ WT-Interceptor focuses solely on WAF logic (simple)
- ✅ Fault tolerance: If Interceptor crashes, Nginx can still serve static files

**When to use:** Nginx already installed on server (auto-detected by installer)

---

**B. Standalone Mode:**
```
Internet → WT-Interceptor (SSL + WAF) → Application
          (Port 443)                    (Port 8080)
```

**Advantages:**
- ✅ Single binary (simpler deployment)
- ✅ Fewer moving parts
- ✅ Lower memory footprint (~64MB less than Nginx+Interceptor)

**When to use:** Fresh server with no existing web server (installer will ask)

#### 3.4.3 Core Features

**1. WAF Rule Engine**
```
Built-in Detection:
- SQL Injection (union select, drop table, etc.)
- XSS (script tags, javascript: protocol)
- Path Traversal (../, directory escape)
- Command Injection (shell metacharacters)
- XXE (XML External Entity)
- SSRF (Server-Side Request Forgery)

Custom Rules (YAML):
waf:
  rules:
    - name: "Custom SQLi Pattern"
      pattern: "(?i)(exec|execute|sp_executesql)"
      target: "query_params"
      action: "BLOCK"
      score: 100
```

**2. Rate Limiting (Per-Path)**
```yaml
rate_limiting:
  limits:
    - path: "/admin/login"
      requests: 5
      window: 60s
      action: "CHALLENGE"
    
    - path: "/api/v1/*"
      requests: 100
      window: 60s
      action: "THROTTLE"
```

**3. Custom Block Pages**
```html
<!-- /etc/watchtower/pages/blocked.html -->
<!DOCTYPE html>
<html>
<head><title>Access Blocked - WatchTower XDR</title></head>
<body>
    <h1>🛡️ Access Blocked</h1>
    <p>Reason: {{REASON}}</p>
    <p>Your IP: {{CLIENT_IP}}</p>
    <p>Incident ID: {{INCIDENT_ID}}</p>
</body>
</html>
```

**4. Real-Time Threat Sharing**
```
Interceptor ──(Unix Socket)──► Sentry ──(gRPC)──► Core
                │
                └──(Redis blocklist)──► Turret

Flow:
1. Interceptor detects SQLi attempt
2. Blocks request, serves custom page
3. Sends threat to Sentry (IPC)
4. Sentry reports to Core
5. Turret bans IP at L3/L4
```

#### 3.4.4 Performance

```
Latency Added: <5ms (p99)
Throughput: 10,000 req/sec
Memory: 128MB base + 1KB per active connection
```

#### 3.4.5 Configuration Example

```yaml
# /etc/watchtower/interceptor.yaml
server:
  mode: "hybrid"
  listen_addr: "127.0.0.1:8081"
  upstream: "http://127.0.0.1:8080"
  
waf:
  enabled: true
  rules_file: "/etc/watchtower/waf_rules.yaml"
  
rate_limiting:
  enabled: true
  backend: "redis"
  redis_url: "127.0.0.1:6379"
  
blocklist:
  source: "redis"
  ttl: 3600
  
custom_pages:
  block_page: "/etc/watchtower/pages/blocked.html"
  rate_limit_page: "/etc/watchtower/pages/rate_limited.html"
  
sentry:
  socket: "/tmp/wt/wt-sentry.sock"
  report_threshold: 50
```


---

## 4. Data Management

### 4.1 Database Schema (PostgreSQL + TimescaleDB)

```sql
-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- =============================================
-- EVENTS (Hypertable - Time-Series Optimized)
-- =============================================
CREATE TABLE events (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ NOT NULL,
    agent_id VARCHAR(50) NOT NULL,
    event_type VARCHAR(30) NOT NULL,
    severity SMALLINT NOT NULL,
    source_ip INET,
    target VARCHAR(100),
    message TEXT,
    metadata JSONB,
    action_taken VARCHAR(20),
    PRIMARY KEY (timestamp, id)
);

SELECT create_hypertable('events', 'timestamp');
SELECT add_retention_policy('events', INTERVAL '120 days');
SELECT add_compression_policy('events', INTERVAL '7 days');

CREATE INDEX idx_events_agent ON events(agent_id, timestamp DESC);
CREATE INDEX idx_events_severity ON events(severity, timestamp DESC);

-- =============================================
-- L7 EVENTS (Application Layer Threats) ⭐ NEW (v1.2)
-- =============================================
CREATE TABLE l7_events (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ NOT NULL,
    agent_id VARCHAR(50) NOT NULL,
    client_ip INET,
    method VARCHAR(10),              -- GET, POST, PUT, DELETE
    path TEXT,
    user_agent TEXT,
    threat_type VARCHAR(50),         -- 'sqli', 'xss', 'path_traversal', 'rate_limit'
    threat_score INT,
    action_taken VARCHAR(20),        -- 'BLOCK', 'CHALLENGE', 'THROTTLE', 'ALLOW'
    request_headers JSONB,
    request_snippet TEXT,            -- First 500 chars (sanitized)
    incident_id VARCHAR(50),
    PRIMARY KEY (timestamp, id)
);

SELECT create_hypertable('l7_events', 'timestamp');
SELECT add_retention_policy('l7_events', INTERVAL '120 days');
SELECT add_compression_policy('l7_events', INTERVAL '7 days');

CREATE INDEX idx_l7_events_agent ON l7_events(agent_id, timestamp DESC);
CREATE INDEX idx_l7_events_threat ON l7_events(threat_type, timestamp DESC);
CREATE INDEX idx_l7_events_ip ON l7_events(client_ip) WHERE client_ip IS NOT NULL;

-- =============================================
-- BASELINES (Seasonal Profiling)
-- =============================================
CREATE TABLE baselines (
    agent_id VARCHAR(50) NOT NULL,
    metric_name VARCHAR(30) NOT NULL,
    day_of_week SMALLINT NOT NULL,
    hour_of_day SMALLINT NOT NULL,
    avg_value NUMERIC(12,4),
    stddev_value NUMERIC(12,4),
    min_value NUMERIC(12,4),
    max_value NUMERIC(12,4),
    sample_count INTEGER,
    last_updated TIMESTAMPTZ,
    PRIMARY KEY (agent_id, metric_name, day_of_week, hour_of_day)
);

-- =============================================
-- AGENTS (Fleet Metadata)
-- =============================================
CREATE TYPE agent_status AS ENUM ('ALIVE', 'STALE', 'DEAD');

CREATE TABLE agents (
    id VARCHAR(50) PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    ip_address INET,
    version VARCHAR(20),
    config_hash CHAR(64),
    status agent_status DEFAULT 'ALIVE',
    last_seen TIMESTAMPTZ,
    registered_at TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB
);

-- =============================================
-- AUDIT LOGS (Tamper-Resistant)
-- =============================================
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    actor VARCHAR(50) NOT NULL,
    action_type VARCHAR(30) NOT NULL,
    target VARCHAR(100),
    reason TEXT,
    snapshot JSONB,
    prev_log_hash CHAR(64),
    signature CHAR(128)
);

-- =============================================
-- CONFIG VERSIONS
-- =============================================
CREATE TABLE config_versions (
    id SERIAL PRIMARY KEY,
    version VARCHAR(20) NOT NULL UNIQUE,
    config_hash CHAR(64) NOT NULL,
    config_yaml TEXT NOT NULL,
    deployed_at TIMESTAMPTZ DEFAULT NOW(),
    author VARCHAR(50),
    changelog TEXT,
    agents_applied JSONB DEFAULT '{}'
);

-- =============================================
-- CERTIFICATES (mTLS Management)
-- =============================================
CREATE TABLE certificates (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(50) UNIQUE NOT NULL,
    cert_pem TEXT NOT NULL,
    key_pem TEXT NOT NULL,
    issued_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT
);

-- =============================================
-- WHITELIST
-- =============================================
CREATE TABLE whitelist (
    id SERIAL PRIMARY KEY,
    ip_address INET NOT NULL UNIQUE,
    added_by VARCHAR(50),
    added_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    reason TEXT,
    active BOOLEAN DEFAULT TRUE
);

-- =============================================
-- UPDATE TRACKING
-- =============================================
CREATE TABLE update_rollouts (
    id SERIAL PRIMARY KEY,
    version VARCHAR(20) NOT NULL,
    binary_hash CHAR(64) NOT NULL,
    initiated_by VARCHAR(50),
    initiated_at TIMESTAMPTZ DEFAULT NOW(),
    status VARCHAR(20) DEFAULT 'IN_PROGRESS',
    target_agents TEXT[],
    completed_agents JSONB DEFAULT '{}',
    rollback_to VARCHAR(20),
    metadata JSONB
);
```

### 4.2 Data Retention & IP Masking

**Retention Policy:**
- Events older than 120 days are deleted
- Monthly cleanup runs on the 1st at 02:00 AM
- After cleanup, data compressed to ~90 days effective

**IP Anonymization (GDPR/KVKK Compliance):**
```sql
-- Mask last octet: 1.2.3.4 → 1.2.3.xxx
CREATE OR REPLACE FUNCTION mask_ip(ip INET) RETURNS TEXT AS $$
BEGIN
    IF FAMILY(ip) = 4 THEN
        RETURN REGEXP_REPLACE(HOST(ip), '\.\d+$', '.xxx');
    ELSE
        RETURN REGEXP_REPLACE(HOST(ip), '(:[0-9a-f]+){4}$', ':xxxx:xxxx:xxxx:xxxx');
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Grafana view (masked)
CREATE VIEW events_masked AS
SELECT 
    id, timestamp, agent_id, event_type, severity,
    mask_ip(source_ip) AS source_ip_masked,
    target, message, action_taken
FROM events;
```

**Configuration:**
```yaml
# /etc/watchtower/core.yaml
privacy:
  ip_masking:
    enabled: true
    grafana_view: "masked"
    admin_override: true  # CLI can unmask
  data_retention:
    events: "120d"
    monthly_cleanup: true
```

---

## 5. Security & Compliance

### 5.1 Authentication Chain

**Layer 1: mTLS (Mutual TLS)**
```
1. Core generates CA:
   openssl genrsa -out ca.key 4096
   openssl req -new -x509 -days 3650 -key ca.key -out ca.crt

2. For each agent:
   openssl genrsa -out agent-web-1.key 2048
   openssl req -new -key agent-web-1.key -out agent-web-1.csr
   openssl x509 -req -in agent-web-1.csr -CA ca.crt -CAkey ca.key -out agent-web-1.crt

3. Agent connects with cert
4. Revocation: UPDATE certificates SET revoked=TRUE WHERE agent_id='web-1'
```

**Layer 2: Bearer Token**
- Secondary authentication (defense-in-depth)
- Rotates every 30 days
- Sent in heartbeat response
- Stored in /etc/watchtower/agent.token (mode 0600)

### 5.2 Network Security

**Core Firewall (iptables):**
```bash
# Default deny
iptables -P INPUT DROP
iptables -P FORWARD DROP

# Allow established
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# gRPC from known agents only
iptables -A INPUT -p tcp --dport 50051 -s 1.2.3.4 -j ACCEPT

# SSH from VPN only
iptables -A INPUT -p tcp --dport 22 -s 10.8.0.0/24 -j ACCEPT

# Grafana from VPN only
iptables -A INPUT -p tcp --dport 8080 -s 10.8.0.0/24 -j ACCEPT
```

**WireGuard VPN:**
```ini
# /etc/wireguard/wg0.conf
[Interface]
PrivateKey = <core_private_key>
Address = 10.8.0.1/24
ListenPort = 51820

[Peer]
PublicKey = <admin_public_key>
AllowedIPs = 10.8.0.2/32
```

### 5.3 Secrets Management

**Never store secrets in config!**
```yaml
# ✅ GOOD
database:
  password_file: "/etc/watchtower/secrets/db_password"
```

**Secrets Structure:**
```
/etc/watchtower/secrets/  (root:watchtower, 0640)
├── db_password
├── ntfy_token
└── agent_tokens/
    ├── web-server-1
    └── blog-server-1
```

---

## 6. Operational Procedures

### 6.1 Initial Deployment

**Core Setup:**
```bash
# 1. Install PostgreSQL + TimescaleDB
sudo apt install postgresql-14 postgresql-14-timescaledb

# 2. Create database
sudo -u postgres psql <<EOF
CREATE DATABASE watchtower;
CREATE USER wt_core WITH PASSWORD 'CHANGE_ME';
GRANT ALL PRIVILEGES ON DATABASE watchtower TO wt_core;
\c watchtower
CREATE EXTENSION timescaledb;
EOF

# 3. Run schema
psql -U wt_core -d watchtower -f schema.sql

# 4. Install Core binary
sudo cp wt-core /usr/local/bin/
sudo chmod +x /usr/local/bin/wt-core

# 5. Initialize PKI (Certificate Authority) ⭐ NEW (v1.1)
wt-cli pki init --output /etc/watchtower/pki/
# Output:
#   ✅ CA private key: /etc/watchtower/pki/ca.key
#   ✅ CA certificate: /etc/watchtower/pki/ca.crt
#   ✅ Serial tracker: /etc/watchtower/pki/ca.srl

# 6. Configure
sudo mkdir -p /etc/watchtower/secrets
sudo nano /etc/watchtower/core.yaml
echo "CHANGE_ME" | sudo tee /etc/watchtower/secrets/db_password

# 7. Create systemd service
sudo tee /etc/systemd/system/wt-core.service <<EOF
[Unit]
Description=WatchTower Core Service
After=network.target postgresql.service

[Service]
Type=simple
User=watchtower
Group=watchtower
ExecStart=/usr/local/bin/wt-core --config /etc/watchtower/core.yaml
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF

# 8. Start
sudo systemctl daemon-reload
sudo systemctl enable wt-core
sudo systemctl start wt-core
```

**Agent Setup (One-Click Installer):** ⭐ NEW (v1.2)
```bash
# ========================================
# STEP 1: Generate Installer (on Core)
# ========================================
wt-cli agent generate-installer --name web-server-1 --type web

# Output:
# 📦 Generated: web-server-1-installer.sh
# 📋 Detected configuration for target:
#    - Server type: web (includes Interceptor)
#    - Expected services: Nginx, Vaultwarden
#    
# 💡 Installer will:
#    ✅ Detect existing Nginx (auto-select Hybrid mode)
#    ✅ Install Sentry + Turret + Interceptor
#    ✅ Deploy certificates
#    ✅ Configure systemd services
#    ✅ Test connectivity to Core
#    
# 🚀 Deploy with:
#    scp web-server-1-installer.sh target:/tmp/
#    ssh target "sudo bash /tmp/web-server-1-installer.sh"

# ========================================
# STEP 2: Transfer Installer
# ========================================
scp web-server-1-installer.sh web-server-1:/tmp/

# ========================================
# STEP 3: Run Installer (on target server)
# ========================================
ssh web-server-1
sudo bash /tmp/web-server-1-installer.sh

# Installer Output:
# 🛡️  WatchTower Agent Installer v1.2
# =====================================
# 
# 🔍 Pre-flight checks:
#    ✅ OS: Ubuntu 22.04 LTS (supported)
#    ✅ Root access: confirmed
#    ✅ Network: Core reachable (core.internal:50051)
#    
# 🔍 Detecting existing services:
#    ✅ Nginx: FOUND (v1.22.1)
#    ✅ SSL: Let's Encrypt detected (vault.example.com)
#    ⚠️  Application: Listening on port 8080 (assumed Vaultwarden)
#    
# 💡 Selected mode: HYBRID
#    - Keep Nginx (SSL termination)
#    - Add WT-Interceptor (WAF layer)
#    - Zero-downtime installation
#    
# 📦 Installing components:
#    [1/5] Downloading binaries... ✅
#    [2/5] Installing Sentry... ✅
#    [3/5] Installing Turret... ✅
#    [4/5] Installing Interceptor (Hybrid mode)... ✅
#    [5/5] Deploying certificates... ✅
#    
# 🔌 Testing connectivity:
#    ✅ Sentry → Core: Connected
#    ✅ Interceptor → Vaultwarden: Responding
#    ✅ Nginx → Interceptor: Configured
#    
# ✅ Installation complete!
# 📊 View status: wt-cli agent status web-server-1

# ========================================
# STEP 4: Verify (on Core)
# ========================================
wt-cli agents list

# Output:
# AGENT_ID       STATUS   VERSION   LAST_SEEN          COMPONENTS
# web-server-1   ALIVE    v1.2.0    2s ago             Sentry, Turret, Interceptor
# blog-server-1  STALE    v1.1.0    95s ago            Sentry, Turret
```

**Installer Smart Detection Logic:**
```bash
# Inside web-server-1-installer.sh

# 1. Detect Nginx
if systemctl is-active --quiet nginx; then
    echo "✅ Nginx detected - Using HYBRID mode"
    INSTALL_MODE="hybrid"
    NGINX_SITES=$(ls /etc/nginx/sites-enabled/)
else
    echo "⚠️  No Nginx detected"
    
    # Ask user
    read -p "Install WT-Interceptor in:
    1) Hybrid mode (install Nginx + Interceptor)
    2) Standalone mode (Interceptor only, handles SSL)
    
    Choice [1]: " choice
    
    case $choice in
        2) INSTALL_MODE="standalone" ;;
        *) INSTALL_MODE="hybrid_fresh" 
           echo "📦 Will install Nginx first..."
           ;;
    esac
fi

# 2. Install based on mode
case $INSTALL_MODE in
    hybrid)
        install_interceptor_behind_nginx
        ;;
    hybrid_fresh)
        install_nginx
        install_interceptor_behind_nginx
        ;;
    standalone)
        install_interceptor_standalone
        configure_letsencrypt
        ;;
esac
```

**Manual Installation (Legacy - for advanced users):**
```bash
# 1. Transfer binaries
scp wt-sentry wt-turret target:/tmp/

# 2. Install
ssh target "sudo cp /tmp/wt-{sentry,turret} /usr/local/bin/"

# 3. Issue certificate bundle (on Core) ⭐ NEW (v1.1)
wt-cli pki issue --agent web-server-1 --output /tmp/web-server-1.zip
# Output:
#   ✅ Certificate bundle: /tmp/web-server-1.zip
#   Contents: agent.crt, agent.key, ca.crt, agent.token, README.txt

# 4. Deploy certificate bundle (automated) ⭐ NEW (v1.1)
wt-cli pki deploy --agent web-server-1 --host target-ip --user root
# Actions:
#   - SSH to target via WireGuard
#   - Create /etc/watchtower/
#   - Upload certs (0600 for .key)
#   - Update Core database
# OR manually:
scp /tmp/web-server-1.zip target:/tmp/
ssh target "cd /tmp && unzip web-server-1.zip && sudo mv agent.* ca.crt /etc/watchtower/"

# 5. Configure
ssh target "sudo nano /etc/watchtower/sentry.yaml"

# 6. Start
ssh target "sudo systemctl start wt-sentry wt-turret"

# 7. Verify
wt-cli agents list
```

### 6.2 Day-to-Day Operations

```bash
# Check health
wt-cli agents list

# View events
wt-cli events tail --agent web-server-1 --lines 50

# Ban IP
wt-cli response ban --ip 1.2.3.4 --reason "Manual" --duration 1h

# Unban
wt-cli response unban --ip 1.2.3.4 --whitelist 24h

# Update config
nano /etc/watchtower/policies/agent_policy.yaml
wt-cli config push --target web-server-1

# Roll out update
wt-cli update rollout --version v1.1.0 --targets all

# Export audit
wt-cli audit export --from 2026-01-01 --to 2026-02-01 --format csv
```

### 6.3 Incident Response

**L4 Alert Procedure:**
```
1. Alert received: "🚨 L4: FIM Change on /etc/passwd"

2. Investigate:
   - SSH to server
   - Check: stat /etc/passwd
   - Review: tail /var/log/watchtower/turret.log

3. Contain:
   - If compromised: wt-cli response isolate --agent web-server-1

4. Forensics:
   - Export timeline: wt-cli events export --agent web-server-1 --hours 24
   - Check quarantine: ls /var/lib/watchtower/quarantine/

5. Recover:
   - Restore from backup
   - Redeploy: wt-cli agents redeploy --agent web-server-1
   - Rotate cert: wt-cli cert rotate --agent web-server-1

6. Document:
   - Post-mortem: wt-cli audit add --event "Incident resolved"
```

### 6.4 Maintenance Procedures ⭐ NEW (v1.1)

#### A. Log Rotation (Critical - Prevents Disk Exhaustion)

**Problem:** WatchTower components write to `/var/log/watchtower/`. Without rotation, logs will fill disk.

**Solution: logrotate Configuration**

```bash
# /etc/logrotate.d/watchtower
/var/log/watchtower/*.log {
    daily                    # Rotate daily
    rotate 7                 # Keep last 7 days
    compress                 # gzip old logs
    delaycompress            # Don't compress most recent
    missingok                # No error if log missing
    notifempty               # Don't rotate empty logs
    create 0640 watchtower watchtower
    sharedscripts
    postrotate
        # Reload services to reopen log files
        systemctl reload wt-turret >/dev/null 2>&1 || true
        systemctl reload wt-sentry >/dev/null 2>&1 || true
    endscript
}

# Critical actions (longer retention for audit)
/var/log/watchtower/turret-actions.log {
    weekly
    rotate 52                # 1 year
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root    # Root-only
}
```

**Installation (during deployment):**
```bash
# Add to install.sh
sudo tee /etc/logrotate.d/watchtower <<'EOF'
# ... (paste config above)
EOF

# Test configuration
sudo logrotate -d /etc/logrotate.d/watchtower

# Force rotation (manual test)
sudo logrotate -f /etc/logrotate.d/watchtower
```

**SIGHUP Handling (Go code must support):**
```go
// cmd/wt-turret/main.go
func main() {
    // ... existing setup ...
    
    // Handle SIGHUP for log rotation
    sighup := make(chan os.Signal, 1)
    signal.Notify(sighup, syscall.SIGHUP)
    
    go func() {
        for range sighup {
            log.Println("SIGHUP received, reopening log files...")
            reopenLogFiles()
        }
    }()
}
```

**systemd Service Update:**
```ini
# /etc/systemd/system/wt-turret.service
[Service]
ExecReload=/bin/kill -HUP $MAINPID  # Enable reload
```

#### B. Certificate Management

**Check Expiring Certificates:**
```bash
# List all certs expiring in <30 days
wt-cli pki check-expiry --warn-days 30

# Output:
#   ⚠️  web-server-1: expires in 25 days (2026-03-05)
#   ✅  blog-server-1: expires in 340 days (2027-01-10)
```

**Renew Certificate:**
```bash
# Single agent
wt-cli pki renew --agent web-server-1

# All expiring certs
wt-cli pki renew-all --grace-period 30d

# Auto-renewal (add to cron)
0 3 * * * /usr/local/bin/wt-cli pki renew-all --grace-period 30d
```

**Revoke Compromised Certificate:**
```bash
wt-cli pki revoke --agent web-server-1 --reason "Security breach"
# Updates database: certificates.revoked = TRUE
# Core rejects connection on next heartbeat
```

#### C. Baseline Maintenance

**Clean Stale Baselines:**
```bash
# Remove baselines for deleted agents
wt-cli baselines cleanup --older-than 90d

# Vacuum database
wt-cli db vacuum
```

**Force Baseline Recalculation:**
```bash
# If baseline seems off (e.g., after major infrastructure change)
wt-cli baselines reset --agent web-server-1 --metric cpu
# Deletes existing baseline, will recalculate over next 7 days
```

#### D. Database Maintenance

**Manual Retention Cleanup:**
```bash
# If automatic cleanup failed
psql -U wt_core watchtower <<EOF
DELETE FROM events WHERE timestamp < NOW() - INTERVAL '120 days';
VACUUM ANALYZE events;
EOF
```

**Disk Space Check:**
```bash
# Monitor TimescaleDB compression
wt-cli db stats

# Output:
#   Events table: 2.3 GB (uncompressed: 8.1 GB)
#   Compression ratio: 3.5x
#   Oldest event: 2025-11-10
#   Newest event: 2026-02-08
```

---

## 7. Development Roadmap

### Phase 0: Preparation (Week 1)
```
✅ Goals:
  - Repository structure
  - Go modules initialized
  - gRPC "Hello World"
  - PKI automation foundation

Deliverables:
  - GitHub repo created ✅
  - cmd/wt-core/main.go
  - cmd/wt-sentry/main.go
  - cmd/wt-cli/main.go (CLI tool skeleton)
  - pkg/protocol/*.proto
  - internal/cache/ (baseline cache stub)
  - Makefile
  - logrotate config template
  - README.md with getting started guide

Success Criteria:
  - Sentry connects to Core via gRPC
  - Send "ping", receive "pong"
  - wt-cli pki init creates CA
  - Log rotation config validated
  - CI/CD pipeline configured (GitHub Actions)
```

### Phase 1: Watcher (Weeks 2-3)
```
Goals:
  - Sentry watches logs + system metrics
  - Core receives and stores events
  - Basic detection patterns

Components:
  Sentry:
    - Log watcher (fsnotify)
    - System monitor (CPU, memory, disk)
    - Pattern matcher (regex engine)
  
  Core:
    - Event receiver (gRPC server)
    - PostgreSQL writer
    - Basic event storage
  
  CLI:
    - wt-cli events list
    - wt-cli events tail
    - wt-cli agents list

Success Criteria:
  - Detect 10 SSH failures in /var/log/auth.log
  - Core writes events to PostgreSQL
  - wt-cli shows events in real-time
  - CPU spike detected (>80% for 5 minutes)
```

### Phase 2: Communication & Monitoring (Week 4)
```
Goals:
  - Heartbeat mechanism (agent health)
  - TimescaleDB integration (time-series)
  - Notifications (ntfy.sh)
  - Basic Grafana dashboard

Components:
  Core:
    - Heartbeat receiver
    - Agent health monitor
    - TimescaleDB hypertables
    - ntfy integration
  
  Sentry:
    - Heartbeat sender (every 30s)
    - Metric collection (uptime, event count)
  
  Dashboard:
    - Grafana data source (PostgreSQL)
    - Panel: Agent status (alive/stale/dead)
    - Panel: Events timeline
    - Panel: CPU/Memory graphs

Success Criteria:
  - Core detects dead agent within 90 seconds
  - Alert sent to phone via ntfy
  - Grafana dashboard shows live data
  - TimescaleDB compression working
```

### Phase 3: Turret (Weeks 5-6) ⚠️ CAUTION
```
Goals:
  - Turret automated response
  - Unix Socket IPC (Sentry ↔ Turret)
  - iptables/ipset integration
  - Safety mechanisms (whitelisting, circuit breaker)

Components:
  Turret:
    - Unix socket server
    - Command validator (whitelist checking)
    - iptables executor
    - ipset manager
    - Circuit breaker (rate limiting)
  
  Sentry:
    - Turret client (Unix socket)
    - Threat scoring
    - Action recommendation

⚠️ CRITICAL: Test in isolated VM only!
  - Use VMware/Multipass
  - DO NOT test on production servers
  - Risk: Self-ban (lockout from server)

Success Criteria:
  - Sentry detects brute force (5 SSH failures)
  - Sends BAN command to Turret
  - Turret adds IP to ipset blacklist
  - IP blocked at kernel level (verify with tcpdump)
  - Whitelist prevents self-ban
  - Circuit breaker triggers on >10 bans/min
  - Rollback works (unban via wt-cli)
```

### Phase 4: Brain (Anomaly Engine) (Weeks 7-8)
```
Goals:
  - Statistical anomaly detection
  - Baseline calculation (7-day rolling window)
  - Baseline cache (in-memory)
  - Advanced Grafana dashboards

Components:
  Core:
    - Baseline calculator
    - Z-Score anomaly detector
    - BaselineCache (Go map, 50MB)
    - Background baseline updater
  
  Database:
    - baselines table (seasonal patterns)
    - Automatic aggregation queries
  
  Dashboard:
    - Panel: Anomaly score timeline
    - Panel: Baseline vs actual (CPU, memory)
    - Panel: Threat heatmap (per agent)
    - Alert rules (anomaly score >80)

Success Criteria:
  - 7-day baseline established for each metric
  - Anomaly detected (CPU spike 3σ above baseline)
  - Grafana shows anomaly alert
  - Cache hit rate >95% (verify with metrics)
  - Baseline recalculates automatically (weekly)
```

### Phase 5: Shield (Network IDS) - DEFERRED
```
Goals:
  - WT-Guard (NIDS component)
  - Packet analysis (libpcap/AF_PACKET)
  - Port scan detection
  - DDoS mitigation

Note: Deferred to v2.0 (post-v1.0 release)
Reason: Core features prioritized first

Components (Planned):
  - Guard: Packet capture agent
  - Signature engine (Suricata-like)
  - Flow analysis (NetFlow v9)
  - Integration with Turret (ban scanning IPs)
```

### Phase 6: Gatekeeper (Application Layer) (Weeks 9-11)
```
Goals:
  - WT-Interceptor component
  - Application layer WAF
  - Custom block pages
  - One-click installer (auto-detection)

Components:
  Interceptor:
    - HTTP reverse proxy (Go net/http)
    - WAF rule engine (SQL injection, XSS, path traversal)
    - Rate limiting (per-path, token bucket)
    - Custom error pages (HTML templates)
    - GeoIP filtering (MaxMind DB)
  
  Installer:
    - Smart Nginx detection
    - Hybrid vs Standalone mode selection
    - Automatic systemd service creation
    - Certificate deployment (embedded)
    - Rollback capability
  
  Integration:
    - Sentry ↔ Interceptor (Unix Socket, L7 threat sharing)
    - Turret ↔ Interceptor (Redis blocklist sync)
    - Core receives L7 events (gRPC)
  
  Dashboard:
    - Panel: L7 threats (SQLi, XSS attempts)
    - Panel: Rate limit violations
    - Panel: Top blocked IPs

Deliverables:
  - cmd/wt-interceptor/main.go
  - internal/waf/rules.go
  - internal/ratelimit/limiter.go
  - web/pages/*.html (block pages)
  - wt-cli agent generate-installer
  - wt-cli agent deploy
  - Database: l7_events table

Success Criteria:
  - Simulate SQLi attack → blocked + custom "WatchTower" page
  - Brute force /admin/login → rate limited → CAPTCHA challenge
  - One-click installer works on:
    * Fresh Ubuntu (no Nginx) → standalone mode
    * Existing Nginx → hybrid mode
  - Performance: <5ms added latency (p99)
  - Cloudflare down → WatchTower protecting independently
```

### Phase 7: Polish & Release (Week 12)
```
Goals:
  - Documentation finalization
  - Performance tuning
  - Security audit
  - v1.0.0 release

Tasks:
  - Complete README.md (installation, quick start)
  - API documentation (wt-cli commands)
  - Deployment guide (AWS, DigitalOcean examples)
  - Performance benchmarks (documented)
  - Security review (third-party if possible)
  - Code cleanup (gofmt, golint, staticcheck)
  - Final integration tests (full topology)
  
Release Checklist:
  - [ ] All unit tests passing (>80% coverage)
  - [ ] Integration tests passing
  - [ ] E2E tests passing (VMware topology)
  - [ ] No critical bugs in issue tracker
  - [ ] Documentation complete
  - [ ] Binaries built (Linux x64, ARM64)
  - [ ] Docker images published
  - [ ] GitHub release notes written
  - [ ] Demo video recorded (YouTube)

v1.0.0 Release Announcement:
  - Blog post (architecture overview)
  - Reddit (r/selfhosted, r/golang, r/netsec)
  - Hacker News submission
  - Twitter/LinkedIn announcement
```

---    - Rate limiting per-path
    - Custom error pages
    - GeoIP filtering (optional)
  
  Installer:
    - Smart detection (Nginx presence)
    - Auto-configuration (Hybrid vs Standalone)
    - Zero-downtime deployment
    - Rollback capability
  
  Integration:
    - Sentry ↔ Interceptor (L7 threat sharing)
    - Turret ↔ Interceptor (shared blocklist)
    - Core receives L7 threat data
    - Grafana L7 metrics dashboard

Deliverables:
  - cmd/wt-interceptor/main.go
  - internal/waf/rules.go
  - internal/ratelimit/limiter.go
  - web/pages/*.html (block pages)
  - wt-cli agent generate-installer
  - Database: l7_events table

Success Criteria:
  - Simulate SQLi → Blocked + custom page
  - Brute force /admin → Rate limited + challenge
  - Cloudflare down → WatchTower protecting
  - Performance: <5ms added latency (p99)
  - One-click installer works on fresh + existing Nginx servers
```

---

## 8. Appendices

### 8.1 Glossary

| Term | Definition |
|------|------------|
| **XDR** | Extended Detection and Response |
| **IDS** | Intrusion Detection System |
| **IPS** | Intrusion Prevention System |
| **HIDS** | Host-based IDS |
| **NIDS** | Network-based IDS |
| **FIM** | File Integrity Monitoring |
| **mTLS** | Mutual TLS |
| **DEFCON** | Defense Condition (threat level) |
| **EMA** | Exponential Moving Average |

### 8.2 Reference Links

**Technology:**
- Go: https://go.dev/doc/
- gRPC: https://grpc.io/docs/languages/go/
- PostgreSQL: https://www.postgresql.org/docs/
- TimescaleDB: https://docs.timescale.com/
- Grafana: https://grafana.com/docs/
- WireGuard: https://www.wireguard.com/

**Security:**
- OWASP: https://owasp.org/
- CIS Benchmarks: https://www.cisecurity.org/
- NIST Framework: https://www.nist.gov/cyberframework

### 8.3 Testing Checklist

**Before Production:**
```
□ Unit tests (>80% coverage)
□ Integration tests
□ Load test (100 agents, 1000 events/sec)
□ Failure scenarios:
  □ Core crash
  □ Network loss
  □ Database failure
  □ Disk full
□ Security audit:
  □ Cert validation
  □ SQL injection
  □ Race conditions
  □ Whitelist bypass
□ Performance:
  □ Heartbeat <100ms p99
  □ Event ingestion <50ms p99
  □ Anomaly detection <10ms
```

### 8.4 wt-cli PKI Commands Reference ⭐ NEW (v1.1)

**Complete CLI tool for certificate management automation.**

#### Initialize PKI (One-time setup)
```bash
wt-cli pki init [OPTIONS]

Options:
  --output PATH           Output directory (default: /etc/watchtower/pki)
  --key-size INT          RSA key size (default: 4096)
  --validity-years INT    CA validity period (default: 10)

Example:
  wt-cli pki init --output /etc/watchtower/pki/
  
Output Files:
  - ca.key      CA private key (4096-bit RSA)
  - ca.crt      CA certificate (self-signed, 10 years)
  - ca.srl      Serial number tracker
```

#### Issue Agent Certificate
```bash
wt-cli pki issue --agent AGENT_ID [OPTIONS]

Options:
  --agent ID              Agent identifier (required)
  --output PATH           Bundle output path (default: /tmp/AGENT_ID.zip)
  --validity-days INT     Certificate validity (default: 365)
  --token                 Generate bearer token (default: true)

Example:
  wt-cli pki issue --agent web-server-1 --output /tmp/web-1.zip
  
Bundle Contents:
  - agent.crt       Client certificate
  - agent.key       Private key (2048-bit RSA)
  - ca.crt          CA certificate (for verification)
  - agent.token     Bearer token (UUID v4)
  - README.txt      Installation instructions
  
Database Update:
  - Inserts into: certificates table
  - Fields: agent_id, cert_pem, key_pem, expires_at
```

#### Deploy Certificate (Automated)
```bash
wt-cli pki deploy --agent AGENT_ID [OPTIONS]

Options:
  --agent ID              Agent to deploy to (required)
  --host HOSTNAME         Target hostname/IP (required)
  --user USERNAME         SSH user (default: root)
  --port INT              SSH port (default: 22)
  --bundle PATH           Certificate bundle (auto-detected if omitted)

Example:
  wt-cli pki deploy --agent web-server-1 --host 10.8.0.3 --user root
  
Actions:
  1. SSH to target (via WireGuard VPN)
  2. Create /etc/watchtower/ if not exists
  3. Upload: agent.crt, agent.key, ca.crt, agent.token
  4. Set permissions: chmod 0600 agent.key agent.token
  5. Verify: Test gRPC connection to Core
  6. Update database: agent deployment timestamp
```

#### Check Certificate Expiry
```bash
wt-cli pki check-expiry [OPTIONS]

Options:
  --warn-days INT         Warning threshold (default: 30)
  --agent ID              Check specific agent (optional)

Example:
  wt-cli pki check-expiry --warn-days 30
  
Output:
  ⚠️  web-server-1: expires in 25 days (2026-03-05)
  ✅  blog-server-1: expires in 340 days (2027-01-10)
  🔴 old-server-3: EXPIRED 5 days ago (2026-02-03)
```

#### Renew Certificate
```bash
wt-cli pki renew --agent AGENT_ID [OPTIONS]

Options:
  --agent ID              Agent to renew (required)
  --validity-days INT     New validity period (default: 365)
  --auto-deploy          Auto-deploy after renewal (default: false)

Example:
  wt-cli pki renew --agent web-server-1 --auto-deploy
  
Actions:
  1. Generate new certificate (same key)
  2. Update database: new expires_at
  3. If --auto-deploy: Push to agent via gRPC
  4. Agent restarts wt-sentry service
  
Bulk Renewal:
  wt-cli pki renew-all --grace-period 30d
  # Renews all certs expiring in <30 days
```

#### Revoke Certificate
```bash
wt-cli pki revoke --agent AGENT_ID [OPTIONS]

Options:
  --agent ID              Agent to revoke (required)
  --reason TEXT           Revocation reason (required)

Example:
  wt-cli pki revoke --agent web-server-1 --reason "Compromised host"
  
Actions:
  1. Update database: certificates.revoked = TRUE
  2. Update database: revocation_reason, revoked_at
  3. Core rejects connection on next heartbeat (90s)
  4. Audit log entry created
  
⚠️  WARNING: Revocation is immediate. Ensure replacement cert ready.
```

#### List Certificates
```bash
wt-cli pki list [OPTIONS]

Options:
  --status STATUS         Filter by status (active/revoked/expired)
  --sort FIELD            Sort by: expires_at, issued_at, agent_id

Example:
  wt-cli pki list --status active --sort expires_at
  
Output:
  AGENT_ID       ISSUED_AT    EXPIRES_AT   STATUS   DAYS_LEFT
  web-server-1   2025-02-08   2026-02-08   active   365
  blog-server-1  2024-03-01   2025-03-01   active   21  ⚠️
  old-server-3   2024-01-01   2025-02-03   expired  -5  🔴
```

#### Export CA Certificate
```bash
wt-cli pki export-ca [OPTIONS]

Options:
  --output PATH           Output file (default: ca.crt)
  --format FORMAT         pem | der (default: pem)

Example:
  wt-cli pki export-ca --output /tmp/watchtower-ca.crt
  
Use Case: Import into browser/OS trust store for Dashboard access
```

### 8.6 Technology Decision Matrix ⭐ NEW (v2.0)

**Complete rationale for every technology choice in WatchTower XDR.**

| **Category** | **WatchTower Choice** | **Alternatives Considered** | **Why We Chose This** | **Why NOT Alternatives** |
|--------------|----------------------|----------------------------|----------------------|--------------------------|
| **Programming Language** | **Go 1.21+** | Python 3.11+, Rust, C++, Java | **Pros:**<br>• Single static binary (no runtime)<br>• Low memory (50MB vs Python 150MB+)<br>• Native concurrency (goroutines)<br>• Fast compilation (seconds)<br>• Excellent network/gRPC libraries<br>• Easy cross-compilation<br>• Strong typing + simple syntax | **Python:**<br>• Runtime dependency (Python 3.x)<br>• GIL bottleneck (no true parallelism)<br>• 3x memory usage<br>• Slower execution<br><br>**Rust:**<br>• Steep learning curve<br>• Slow compilation<br>• Complex borrow checker<br><br>**C++:**<br>• Memory safety issues<br>• Complex build systems<br>• Manual memory management<br><br>**Java:**<br>• JVM overhead (~200MB)<br>• Large binaries<br>• Slow startup |
| **RPC Framework** | **gRPC + Protobuf** | REST API + JSON, GraphQL, WebSockets, MQTT | **Pros:**<br>• Type-safe (Protobuf schema enforced)<br>• Bi-directional streaming<br>• Built-in load balancing<br>• mTLS native support<br>• 7x faster than JSON/REST<br>• Code generation (no manual serialization)<br>• HTTP/2 multiplexing | **REST + JSON:**<br>• No streaming support<br>• JSON parsing overhead<br>• No type safety<br>• Manual API versioning<br><br>**GraphQL:**<br>• Overkill for simple agent-core<br>• Query complexity attacks<br>• No streaming<br><br>**WebSockets:**<br>• No type safety<br>• Manual protocol design<br>• No load balancing<br><br>**MQTT:**<br>• IoT-focused (not server security)<br>• No request/response pattern<br>• Pub/sub overhead |
| **Primary Database** | **PostgreSQL 14+** | MySQL 8+, MongoDB, SQLite, ClickHouse | **Pros:**<br>• ACID compliance (data integrity)<br>• JSONB for flexible metadata<br>• Mature (30+ years, battle-tested)<br>• Strong community & ecosystem<br>• TimescaleDB extension (same DB)<br>• Advanced indexing (GiST, GIN)<br>• Full-text search built-in | **MySQL:**<br>• Weaker JSON support<br>• Less advanced features<br>• Oracle ownership concerns<br><br>**MongoDB:**<br>• No ACID transactions (pre-4.0)<br>• Schema-less = data inconsistency risk<br>• Higher memory usage<br><br>**SQLite:**<br>• Single-writer bottleneck<br>• No multi-server support<br>• Limited concurrency<br><br>**ClickHouse:**<br>• Columnar (overkill for OLTP)<br>• Complex setup<br>• Not general-purpose |
| **Time-Series Extension** | **TimescaleDB** | InfluxDB, Prometheus, Graphite, Native PostgreSQL | **Pros:**<br>• PostgreSQL extension (same DB!)<br>• SQL queries (familiar syntax)<br>• Automatic partitioning<br>• Compression built-in (3-10x)<br>• No separate daemon<br>• Hypertables = transparent | **InfluxDB:**<br>• Separate service (more complexity)<br>• InfluxQL learning curve<br>• No SQL joins<br>• Community edition limits<br><br>**Prometheus:**<br>• Pull model (not push)<br>• Limited long-term storage<br>• PromQL learning curve<br><br>**Graphite:**<br>• Carbon + Whisper complexity<br>• Storage format inflexible<br>• Manual setup pain<br><br>**Native PostgreSQL:**<br>• Manual partitioning (error-prone)<br>• No automatic compression<br>• Slow without optimization |
| **VPN** | **WireGuard** | Tailscale, OpenVPN, IPsec/IKEv2, ZeroTier | **Pros:**<br>• Modern, audited codebase<br>• Kernel-level (fast)<br>• Simple config (20 lines)<br>• Low overhead (<100KB RAM)<br>• Self-hosted (no SaaS)<br>• Cross-platform | **Tailscale:**<br>• SaaS dependency (not self-hosted)<br>• Coordination server required<br>• Privacy concerns (metadata)<br><br>**OpenVPN:**<br>• Complex config (100+ lines)<br>• Slower (userspace)<br>• Certificate management pain<br><br>**IPsec:**<br>• Very difficult setup<br>• Old, complex protocol<br>• Poor firewall traversal<br><br>**ZeroTier:**<br>• Centralized controller<br>• Network not truly self-hosted |
| **Notification Service** | **ntfy.sh** | Pushover, Telegram Bot, Slack Webhooks, Email SMTP | **Pros:**<br>• Self-hostable (Docker image)<br>• HTTP-based (simple integration)<br>• No API keys required<br>• Multi-platform (iOS, Android, Web)<br>• Priority/attachment support<br>• Open source | **Pushover:**<br>• Paid service ($5 one-time, but still SaaS)<br>• API rate limits<br>• Not self-hosted<br><br>**Telegram:**<br>• Bot setup complex<br>• Telegram account required<br>• Rate limits strict<br><br>**Slack:**<br>• Webhook rate limits<br>• Enterprise pricing for features<br>• Not designed for alerts<br><br>**Email:**<br>• SMTP unreliable<br>• Spam filters block alerts<br>• Slow delivery |
| **Dashboard** | **Grafana 10+** | Custom React App, Kibana, Metabase, Splunk | **Pros:**<br>• Industry standard (known by ops teams)<br>• PostgreSQL plugin native<br>• Zero custom UI code<br>• Alert rules built-in<br>• Open source (Apache 2.0)<br>• Rich time-series visualizations | **Custom React:**<br>• Months of development time<br>• Maintenance burden<br>• Reinventing the wheel<br><br>**Kibana:**<br>• ElasticSearch dependency<br>• Heavy resource usage<br>• Complex setup<br><br>**Metabase:**<br>• Limited time-series viz<br>• Business analytics focus<br>• Slower for real-time<br><br>**Splunk:**<br>• Enterprise pricing ($$$$$)<br>• Closed source<br>• Overkill for SMB |
| **Configuration Format** | **YAML** | JSON, TOML, HCL, INI | **Pros:**<br>• Human-readable<br>• Comments supported<br>• Kubernetes-like (familiar)<br>• Go stdlib (gopkg.in/yaml.v3)<br>• Hierarchical structure | **JSON:**<br>• No comments (painful)<br>• Verbose for nested data<br>• Trailing comma errors<br><br>**TOML:**<br>• Less familiar<br>• Deep nesting awkward<br>• Limited adoption<br><br>**HCL:**<br>• Terraform-specific<br>• Not general-purpose<br><br>**INI:**<br>• Limited nesting<br>• No arrays/maps<br>• Too simple |
| **File Monitoring** | **fsnotify (inotify)** | Polling (tail -f), Filebeat, Fluentd | **Pros:**<br>• Kernel events (instant notification)<br>• Zero polling overhead<br>• Built-in Go library<br>• Cross-platform (Linux, macOS, Windows) | **Polling:**<br>• CPU waste (constant checks)<br>• Delayed detection<br>• Scales poorly<br><br>**Filebeat:**<br>• Separate daemon<br>• ElasticSearch ecosystem lock-in<br>• Heavier than needed<br><br>**Fluentd:**<br>• Ruby dependency<br>• Complex configuration<br>• Designed for log shipping |
| **Firewall Management** | **iptables + ipset** | nftables, ufw, Custom Kernel Module | **Pros:**<br>• Universal (kernel 2.4+ = 2001)<br>• Battle-tested (20+ years)<br>• ipset = O(1) lookup (10,000+ IPs)<br>• Well-documented<br>• No learning curve | **nftables:**<br>• Newer (less battle-tested)<br>• Not on all distros yet<br>• Syntax learning curve<br><br>**ufw:**<br>• Abstraction layer (slower)<br>• Less control<br>• Ubuntu-specific bias<br><br>**Custom Module:**<br>• Kernel development risk<br>• Kernel API changes<br>• Compile dependency |
| **Container Support** | **Optional (systemd primary)** | Docker Required, Kubernetes-Only | **Pros:**<br>• Direct systemd (simpler for VPS)<br>• Container support as option<br>• Less overhead<br>• Easier debugging | **Docker Required:**<br>• Adds complexity for simple VPS<br>• Docker daemon dependency<br>• Networking overhead<br><br>**K8s-Only:**<br>• Massive overkill for SMB<br>• Steep learning curve<br>• Resource intensive |

### **Key Decision Principles:**

1. **Self-Hosted First:** Avoid SaaS dependencies (Tailscale ❌ → WireGuard ✅)
2. **Battle-Tested Over New:** Prefer mature tech (PostgreSQL ✅ > MongoDB ❌)
3. **Simplicity:** Fewer moving parts (TimescaleDB extension ✅ vs separate InfluxDB ❌)
4. **Performance:** Native speed (Go ✅, gRPC ✅ vs Python/REST ❌)
5. **Low Barrier to Entry:** Standard tools (iptables ✅ vs custom kernel module ❌)
6. **No Vendor Lock-In:** Open source, self-hostable, portable

### 8.7 Development Workflow & Testing Strategy ⭐ NEW (v2.0)

**Complete guide for developing WatchTower with Antigravity (or Claude Code) and testing in isolated environments.**

#### A. Development Environment Setup

**Prerequisites:**
```bash
# Go 1.21+
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Protocol Buffers compiler
sudo apt install -y protobuf-compiler
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# VMware Workstation 17 Pro (for complex testing)
# Already installed ✅

# Multipass (for quick testing)
sudo snap install multipass
```

**Project Structure:**
```
watchtower-xdr/
├── cmd/
│   ├── wt-core/         # Core server
│   ├── wt-sentry/       # Agent (HIDS)
│   ├── wt-turret/       # Agent (IPS)
│   ├── wt-interceptor/  # Agent (WAF)
│   └── wt-cli/          # Management CLI
├── internal/            # Private packages
│   ├── core/
│   ├── sentry/
│   ├── turret/
│   ├── interceptor/
│   └── analysis/        # Anomaly detection (Strategy Pattern)
├── pkg/                 # Public packages
│   ├── protocol/        # gRPC protobuf
│   └── logger/
├── scripts/
│   ├── train_model.py   # ML training (offline)
│   └── e2e-test.sh      # End-to-end test
├── test/
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── deployments/
│   ├── docker-compose.test.yml
│   └── k8s/
├── docs/
│   ├── ARCHITECTURE.md  # This document
│   ├── DEVLOG.md        # Development journal
│   └── API.md
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

#### B. Development Cycle (Antigravity + Claude)

**Daily Workflow:**
```
┌─────────────────────────────────────────┐
│  1. DESIGN (Antigravity/Claude)         │
│     Prompt: "Implement LogWatcher       │
│              with fsnotify"             │
│     Claude generates:                   │
│     - logwatcher.go                     │
│     - logwatcher_test.go                │
│     - Usage example                     │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│  2. LOCAL DEV (Your Machine)            │
│     - Copy code from Claude             │
│     - go run cmd/wt-sentry/main.go      │
│     - go test ./internal/sentry/        │
│     - Fix compilation errors            │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│  3. QUICK TEST (Multipass - 2 min)      │
│     multipass launch ubuntu-test        │
│     multipass transfer wt-sentry        │
│     multipass exec ubuntu-test          │
│     sudo /tmp/wt-sentry --test          │
│     multipass delete ubuntu-test        │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│  4. INTEGRATION TEST (VMware - weekly)  │
│     Start core-vm + agent-vm            │
│     Test gRPC communication             │
│     Simulate attack                     │
│     Verify ban in iptables              │
│     Snapshot "working-v0.3.0"           │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│  5. COMMIT & PUSH                       │
│     git add .                           │
│     git commit -m "feat: LogWatcher"    │
│     git push origin feat/log-watcher    │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│  6. CI/CD (GitHub Actions)              │
│     - go test ./...                     │
│     - go build (Linux/ARM)              │
│     - Docker integration test           │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│  7. STAGING (Real VPS - before release) │
│     Deploy to Oracle Free Tier          │
│     Run for 24-48 hours                 │
│     Monitor Grafana                     │
└─────────────────────────────────────────┘
```

#### C. Testing Levels

**Level 1: Unit Tests (Go - Local)**
```go
// internal/sentry/logwatcher_test.go
func TestLogWatcher_DetectSSHBruteForce(t *testing.T) {
    // Create temp log file
    tmpfile, _ := os.CreateTemp("", "auth.log")
    defer os.Remove(tmpfile.Name())
    
    // Write fake SSH failures
    for i := 0; i < 5; i++ {
        tmpfile.WriteString(fmt.Sprintf(
            "Feb 8 14:30:%02d sshd[1234]: Failed password for root from 1.2.3.4\n", i,
        ))
    }
    tmpfile.Sync()
    
    // Test watcher
    watcher := NewLogWatcher(tmpfile.Name())
    events, _ := watcher.Scan()
    
    // Assert
    if len(events) != 5 {
        t.Errorf("Expected 5 events, got %d", len(events))
    }
}

// Run: go test -v ./internal/sentry/
```

**Level 2: Integration Tests (Docker Compose)**
```yaml
# docker-compose.test.yml
version: '3.8'
services:
  postgres:
    image: timescale/timescaledb:latest-pg14
    environment:
      POSTGRES_DB: watchtower_test
      POSTGRES_PASSWORD: test
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5
  
  core:
    build: .
    command: /usr/local/bin/wt-core --config /etc/watchtower/core.test.yaml
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - ./test/configs:/etc/watchtower
  
  agent:
    build: .
    command: /usr/local/bin/wt-sentry --config /etc/watchtower/sentry.test.yaml
    depends_on:
      - core
```

```bash
# Run integration tests
docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit
docker-compose -f docker-compose.test.yml down -v
```

**Level 3: Quick VM Test (Multipass - Daily)**
```bash
# scripts/quick-test-multipass.sh
#!/bin/bash
set -e

VM_NAME="wt-test-$(date +%s)"

echo "🚀 Launching VM..."
multipass launch --name $VM_NAME --cpus 2 --mem 2G --disk 5G

echo "📦 Transferring binary..."
go build -o wt-sentry cmd/wt-sentry/main.go
multipass transfer wt-sentry $VM_NAME:/tmp/

echo "🧪 Running test..."
multipass exec $VM_NAME -- bash <<'EOF'
sudo /tmp/wt-sentry --version
echo "Feb 8 14:30:00 sshd[1234]: Failed password" | sudo tee -a /var/log/auth.log
sudo timeout 10s /tmp/wt-sentry --config /tmp/test.yaml || true
EOF

echo "🧹 Cleanup..."
multipass delete $VM_NAME --purge

echo "✅ Quick test passed"
```

**Level 4: Complex Topology (VMware - Weekly)**
```bash
# scripts/vmware-integration-test.ps1
$VMRUN = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"

# VMs
$CORE_VM = "C:\VMs\wt-core\wt-core.vmx"
$WEB_VM = "C:\VMs\wt-agent-web\wt-agent-web.vmx"
$DB_VM = "C:\VMs\wt-agent-db\wt-agent-db.vmx"

# Start all VMs
& $VMRUN -T ws start $CORE_VM nogui
& $VMRUN -T ws start $WEB_VM nogui
& $VMRUN -T ws start $DB_VM nogui

Start-Sleep -Seconds 60  # Wait for boot

# Get IPs
$CORE_IP = & $VMRUN -T ws getGuestIPAddress $CORE_VM
$WEB_IP = & $VMRUN -T ws getGuestIPAddress $WEB_VM

# Deploy binaries
scp .\wt-core.exe user@${CORE_IP}:/tmp/
scp .\wt-sentry.exe user@${WEB_IP}:/tmp/
scp .\wt-turret.exe user@${WEB_IP}:/tmp/

# Start services
ssh user@$CORE_IP "sudo systemctl start wt-core"
ssh user@$WEB_IP "sudo systemctl start wt-sentry wt-turret"

# Simulate attack
ssh user@$WEB_IP "for i in {1..10}; do echo 'Failed password from 1.2.3.4' >> /var/log/auth.log; done"

Start-Sleep -Seconds 10

# Verify ban
$ban_check = ssh user@$WEB_IP "sudo ipset list | grep 1.2.3.4"
if ($ban_check) {
    Write-Host "✅ Integration test passed - IP banned"
} else {
    Write-Host "❌ Integration test failed - IP not banned"
    exit 1
}

# Snapshot (if passed)
& $VMRUN -T ws snapshot $WEB_VM "working-v0.3.0"

# Stop VMs
& $VMRUN -T ws stop $CORE_VM
& $VMRUN -T ws stop $WEB_VM
& $VMRUN -T ws stop $DB_VM
```

#### D. Git Workflow

```bash
# Feature branch development
git checkout -b feat/dynamic-service-discovery

# Daily commits (small, atomic)
git add internal/sentry/services.go
git commit -m "feat(sentry): add systemd service detection"

git add internal/sentry/logpath.go
git commit -m "feat(sentry): implement log path detection heuristics"

# Push to remote
git push origin feat/dynamic-service-discovery

# Create PR on GitHub
# After review, merge to main
```

**Commit Message Convention:**
```
feat(component): short description
fix(component): bug description
docs: documentation update
test: add/update tests
refactor: code refactoring
perf: performance improvement

Examples:
feat(sentry): implement fsnotify log watcher
fix(turret): prevent self-ban on localhost
docs: update deployment guide for AWS
test(interceptor): add SQLi detection tests
```

#### E. Development Journal (Track Progress)

```markdown
# DEVLOG.md

## 2026-02-15 - Faz 0.1: gRPC Protocol Definition
**Status:** ✅ Complete
**Time:** 4 hours
**What I Did:**
- Created agent.proto with Heartbeat RPC
- Generated Go code with protoc
- Tested with grpcurl

**Blockers:** None
**Learnings:** Protobuf field numbering is immutable!
**Next:** Faz 0.2 - Implement Core gRPC server

---

## 2026-02-18 - Faz 1.1: Log Watcher
**Status:** 🟡 In Progress
**Time:** 6 hours (ongoing)
**What I Did:**
- [x] fsnotify integration
- [x] Regex pattern matching (SSH, SQLi)
- [x] Unit tests
- [ ] PostgreSQL writer (TODO)

**Blockers:** 
- TimescaleDB Docker setup failing (port conflict)
- Solution: Changed port to 5433

**Claude Sessions:**
- https://claude.ai/chat/abc123 (fsnotify)
- https://claude.ai/chat/def456 (regex patterns)

**Next:** Complete DB writer, integration test

---

## 2026-02-20 - Multipass vs VMware Decision
**Decision:** Use both!
- Multipass: Daily quick tests
- VMware: Weekly integration tests

**Rationale:** See ARCHITECTURE.md v2.0 Section 8.7
```

#### F. Claude Prompting Template

```markdown
# Daily Session Prompt Template

## Context
- Project: WatchTower XDR (Go-based security platform)
- Current Phase: Faz [X.Y] - [Component Name]
- Last session: [Summary of what was done]
- Repository: https://github.com/[username]/watchtower-xdr
- Architecture: See docs/ARCHITECTURE.md v2.0

## Current Task
[Detailed description of what you want to implement]

## Requirements
1. [Requirement 1]
2. [Requirement 2]
3. [Requirement 3]

## File Structure
internal/[component]/
├── [existing_file].go (DON'T MODIFY)
└── [new_file].go (CREATE THIS)

## Database Schema (if relevant)
[Paste relevant schema from ARCHITECTURE.md]

## Expected Interface
```go
// Expected usage in main.go
component := NewComponent(config)
result, err := component.Method(input)
```

## Deliverables
1. [new_file].go - Implementation
2. [new_file]_test.go - Unit tests (>80% coverage)
3. Example usage in cmd/wt-*/main.go
4. Update to docs/ if needed

## Testing
- Unit test command: go test -v ./internal/[component]/
- Integration test: [specific scenario]
- Success criteria: [measurable outcome]
```

#### G. CI/CD Pipeline

```yaml
# .github/workflows/test-and-build.yml
name: Test & Build

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y protobuf-compiler
          go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
          go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
      
      - name: Generate protobuf
        run: make proto
      
      - name: Run unit tests
        run: go test -v -race -coverprofile=coverage.out ./...
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.out
  
  build:
    needs: test
    runs-on: ubuntu-latest
    strategy:
      matrix:
        goos: [linux]
        goarch: [amd64, arm64]
    steps:
      - uses: actions/checkout@v3
      
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Build binaries
        run: |
          GOOS=${{ matrix.goos }} GOARCH=${{ matrix.goarch }} \
          go build -ldflags="-s -w" -o wt-core-${{ matrix.goos }}-${{ matrix.goarch }} cmd/wt-core/main.go
          
          GOOS=${{ matrix.goos }} GOARCH=${{ matrix.goarch }} \
          go build -ldflags="-s -w" -o wt-sentry-${{ matrix.goos }}-${{ matrix.goarch }} cmd/wt-sentry/main.go
      
      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: binaries-${{ matrix.goos }}-${{ matrix.goarch }}
          path: wt-*
```

**Summary:**
- **Daily dev:** Antigravity/Claude → Local → Multipass (2 min test)
- **Weekly integration:** VMware (3 VMs, complex scenarios, snapshots)
- **Continuous:** GitHub Actions (automated tests on every push)
- **Staging:** Real VPS (24h soak test before release)

### 8.5 wt-cli Agent Management Commands ⭐ NEW (v1.2)

**Complete CLI tool for one-click agent deployment and management.**

#### Generate Installer
```bash
wt-cli agent generate-installer --name AGENT_ID [OPTIONS]

Options:
  --name ID               Agent identifier (required)
  --type TYPE             Agent type: web, db, generic (default: generic)
  --include COMPONENTS    Components: sentry,turret,interceptor (default: auto)
  --output PATH           Installer output path (default: ./AGENT_ID-installer.sh)

Example:
  wt-cli agent generate-installer --name web-server-1 --type web
  
Generated Files:
  - web-server-1-installer.sh     Executable installer script
  - web-server-1-certs.zip        Certificate bundle (embedded)
  
Installer Features:
  ✅ Auto-detects existing Nginx
  ✅ Smart mode selection (Hybrid vs Standalone)
  ✅ Zero-downtime deployment
  ✅ Automatic service configuration
  ✅ Post-install connectivity test
  ✅ Rollback on failure
  
Agent Types:
  - web: Includes Interceptor (WAF layer)
  - db: Sentry + Turret only (no HTTP layer)
  - generic: Sentry + Turret (flexible)
```

#### Deploy Agent
```bash
wt-cli agent deploy --name AGENT_ID --host HOSTNAME [OPTIONS]

Options:
  --name ID               Agent identifier (required)
  --host HOSTNAME         Target server hostname/IP (required)
  --user USERNAME         SSH user (default: root)
  --port INT              SSH port (default: 22)
  --installer PATH        Custom installer (default: auto-generated)

Example:
  wt-cli agent deploy --name web-server-1 --host 192.168.1.100
  
Actions:
  1. Generate installer (if not exists)
  2. SCP installer to target
  3. SSH and execute installer
  4. Monitor installation progress
  5. Verify agent registration in Core
  6. Display connection status
  
Output:
  🚀 Deploying agent: web-server-1
  📦 Generating installer... ✅
  📤 Uploading to 192.168.1.100... ✅
  ⚙️  Running installer...
     [1/5] Pre-flight checks... ✅
     [2/5] Installing components... ✅
     [3/5] Configuring services... ✅
     [4/5] Testing connectivity... ✅
     [5/5] Cleanup... ✅
  
  ✅ Agent deployed successfully!
  📊 Status: wt-cli agent status web-server-1
```

#### List Agents
```bash
wt-cli agent list [OPTIONS]

Options:
  --status STATUS         Filter: alive, stale, dead (optional)
  --components COMPONENT  Filter by component: sentry, turret, interceptor
  --format FORMAT         Output: table, json, yaml (default: table)

Example:
  wt-cli agent list --status alive
  
Output:
  AGENT_ID       STATUS   VERSION   LAST_SEEN   COMPONENTS
  web-server-1   ALIVE    v1.2.0    5s ago      Sentry, Turret, Interceptor
  blog-server-1  ALIVE    v1.2.0    8s ago      Sentry, Turret, Interceptor
  db-server-1    STALE    v1.1.0    95s ago     Sentry, Turret
  old-server-1   DEAD     v1.0.0    5m ago      Sentry
```

#### Agent Status (Detailed)
```bash
wt-cli agent status --name AGENT_ID

Example:
  wt-cli agent status --name web-server-1
  
Output:
  🛡️  WatchTower Agent: web-server-1
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Status:        ALIVE (Last seen: 3s ago)
  Version:       v1.2.0
  Uptime:        2d 14h 32m
  
  Components:
    ✅ Sentry     Running (PID: 1234)
    ✅ Turret     Running (PID: 1235)
    ✅ Interceptor Running (PID: 1236, Mode: Hybrid)
  
  Recent Activity:
    - 2026-02-08 14:30:15  [L3] Banned IP 1.2.3.4 (SSH brute force)
    - 2026-02-08 14:25:03  [L7] Blocked SQLi attempt from 5.6.7.8
    - 2026-02-08 14:20:47  [L2] Rate limited /admin/login (10 req/min)
  
  Metrics (Last 5 min):
    CPU:       12.3% avg
    Memory:    234 MB
    Events:    47 processed, 3 blocked
    Threats:   2 detected (1 L3, 1 L7)
```

#### Remove Agent
```bash
wt-cli agent remove --name AGENT_ID [OPTIONS]

Options:
  --name ID               Agent to remove (required)
  --purge-data           Delete historical data from database
  --revoke-cert          Revoke agent certificate
  --force                Skip confirmation prompt

Example:
  wt-cli agent remove --name old-server-1 --purge-data --revoke-cert
  
Actions:
  1. Mark agent as "DELETED" in database
  2. Revoke certificate (if --revoke-cert)
  3. Delete historical events (if --purge-data)
  4. Send shutdown signal to agent (if reachable)
  
Warning:
  ⚠️  This will permanently remove agent: old-server-1
  ⚠️  Historical data will be deleted (--purge-data specified)
  
  Are you sure? [y/N]: y
  
  ✅ Agent removed from fleet
  ✅ Certificate revoked
  ✅ Historical data purged (342 events deleted)
```

#### Update Agent
```bash
wt-cli agent update --name AGENT_ID --version VERSION [OPTIONS]

Example:
  wt-cli agent update --name web-server-1 --version v1.3.0
  
Actions:
  1. Download new binaries to Core
  2. Send update notification to agent (gRPC)
  3. Agent downloads binaries
  4. Agent verifies checksums
  5. Agent performs rolling restart
  6. Agent reports new version
  
Output:
  🔄 Updating agent: web-server-1 → v1.3.0
  📥 Downloading binaries... ✅
  📤 Pushing to agent... ✅
  ⚙️  Agent updating...
     - Stopping services... ✅
     - Replacing binaries... ✅
     - Starting services... ✅
     - Verifying health... ✅
  
  ✅ Update complete!
  📊 New version: v1.3.0 (uptime: 5s)
```

---

## 🎯 Final Checklist (v2.1)

**Architecture:** ✅ Universal, Cloud-Agnostic, Production-Ready  
**Language:** ✅ Fully English (internationalized)  
**Author:** ✅ Emir Furkan Ulu (corrected)  
**Repository:** ✅ GitHub created (implementation started)  

**Infrastructure Support:**
- [x] AWS, DigitalOcean, Hetzner, Linode, Vultr, OVH
- [x] On-premise (Proxmox, VMware, Hyper-V)
- [x] Hybrid cloud deployments
- [x] Edge devices (Raspberry Pi, ARM)
- [x] Container platforms (Docker, Kubernetes)

**Coverage Layers:**
- [x] Network Layer (L3/L4) - Turret + ipset
- [x] Application Layer (L7) - Interceptor (WAF)
- [x] Endpoint Layer - Sentry + FIM
- [x] Centralized Correlation - Core (Anomaly Engine)

**Critical Features:**
- [x] Baseline Cache (DB bottleneck prevention)
- [x] PKI Automation (wt-cli pki commands)
- [x] Pre-Emptive Throttling (race condition mitigation)
- [x] Log Rotation (disk management)
- [x] Application WAF (WT-Interceptor)
- [x] One-Click Installer (smart detection)
- [x] Custom Block Pages
- [x] ML-Ready Architecture (Strategy Pattern)
- [x] Dynamic Service Discovery (Web UI)
- [x] Technology Decision Matrix
- [x] Development Workflow (VMware + Multipass)

**Documentation Quality:**
- [x] Enterprise-Grade ✅
- [x] Fully English (no Turkish except proper nouns) ✅
- [x] Versioning Clear (Code: v0.x.0 | Docs: v2.1.0) ✅
- [x] Testing Strategy (4-Level) ✅
- [x] Development Roadmap Optimized ✅

**Implementation Status:**
1. ✅ Architecture v2.1 complete
2. ✅ GitHub repo created: watchtower-xdr
3. ✅ Initial commit made
4. ⏳ Phase 0 in progress: gRPC protocol
5. ⏳ CI/CD setup (GitHub Actions)
6. ⏳ VMware test topology (Core + 2 agents)
7. ⏳ Phase 1-7 implementation (iterative)

---

**Document Version:** 2.1.0 (Fully Internationalized)  
**Code Version:** v0.1.0-alpha (in development)  
**Created:** 2026-02-08  
**Last Revised:** 2026-02-08 (English translation, roadmap optimization, author correction)  
**Status:** Implementation Ready 🚀

**Revision Summary:**
- v1.0: Initial architecture design
- v1.1: Implementation feasibility (performance, automation, safety)
- v1.2: Application layer protection (WT-Interceptor, installer, full XDR)
- v2.0: Universal design (any cloud, ML-ready, dev workflow)
- v2.1: **Full English translation, optimized roadmap, author correction**

**Key Achievement (v2.1):** 
WatchTower documentation is now fully internationalized and accessible to the global open-source community. The development roadmap has been optimized with clearer phase breakdowns and success criteria. GitHub repository has been created and initial development has begun.

**Production Readiness:**
- ✅ Cloud-agnostic (no vendor lock-in)
- ✅ Technology choices justified (Section 8.6)
- ✅ ML-ready (Strategy Pattern, easy swap)
- ✅ Test strategy defined (VMware + Multipass + CI/CD)
- ✅ Development workflow documented (Section 8.7)
- ✅ Fully English documentation
- ✅ Scalable (1 to 1000+ agents)
- ✅ GitHub repository established

**"Single Source of Truth" - Return here whenever in doubt.**

**Contributors Welcome:** 
Architecture is stable and fully documented in English. Ready for global open-source contributions. See Section 8.7 for development workflow. GitHub: [repository link to be added]
