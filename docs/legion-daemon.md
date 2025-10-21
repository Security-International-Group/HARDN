![HARDN Logo](docs/assets/IMG_1233.jpeg)
# HARDN Legion Daemon – Full Architecture (with SQLite Baseline System)

```mermaid
graph TD

%% ===================== ENTRYPOINTS =====================
U[User / GUI] -->|commands & configuration| API[HARDN API]
CLI[hardn legion CLI] -->|interactive mode| ISM[Interactive Scanning Mode]
API -->|control plane| LDS[Legion Daemon Service]

%% ===================== MODES =====================
subgraph Modes
  ISM[Interactive Scanning Mode]
  DMN[Daemon Monitoring Mode]
end

ISM -->|single-run analysis| CORE[LegionCore Orchestrator]
DMN -->|continuous monitoring loop| CORE

%% ===================== LEGION CORE =====================
subgraph LegionCore Framework
  direction TB
  COL[Collection Layer]
  ANA[Analysis Layer]
  RESP[Response Layer]
  BASE[Baseline Manager]
  ML[Machine Learning Engine]
  SQL[(SQLite Baseline DB)]
  LOG[Structured Logger]
  ALR[Alert Engine]
  CORE --> COL
  COL --> ANA
  ANA --> RESP
  ANA --> ML
  ML --> BASE
  BASE --> SQL
  RESP --> ALR
  ALR --> LOG
end

%% ===================== SUBSYSTEM DETAILS =====================
subgraph Collection Layer
  direction TB
  SYS[System Telemetry]
  PROC[Process Metrics]
  NET[Network Metrics]
  FS[Filesystem Stats]
  KRN[Kernel Parameters]
  COL --> SYS
  COL --> PROC
  COL --> NET
  COL --> FS
  COL --> KRN
end

subgraph Analysis Layer
  direction TB
  HEUR[Heuristic Engine]
  SIGN[Signature Engine]
  ANOM[Anomaly Detector]
  ANA --> HEUR
  ANA --> SIGN
  ANA --> ANOM
end

subgraph Response Layer
  direction TB
  POL[Policy Evaluator]
  ACT[Response Executor]
  RESP --> POL
  POL --> ACT
end

subgraph Baseline Manager
  direction TB
  CMP[Baseline Comparator]
  UPD[Baseline Updater]
  BASE --> CMP
  BASE --> UPD
  SQL --> CMP
  UPD --> SQL
end

%% ===================== SYSTEM INTEGRATIONS =====================
subgraph Linux Services
  direction TB
  SYSMD[systemd]
  JRN[journald]
  NETM[NetworkManager]
  CRON[cron]
end

LDS --> SYSMD
LDS --> JRN
LDS --> NETM
LDS --> CRON
LOG --> JRN

%% ===================== DATA FLOWS =====================
SQL -->|baseline data| ML
ML -->|heuristic features| ANA
ANA -->|findings| RESP
ALR -->|alerts| U
LOG -->|telemetry logs| API

%% ===================== CLASSES =====================
classDef entry fill:#f0f4ff,stroke:#3b82f6,color:#1e3a8a;
classDef daemon fill:#fef9c3,stroke:#ca8a04,color:#713f12;
classDef layer fill:#ecfccb,stroke:#84cc16,color:#365314;
classDef db fill:#e0f2fe,stroke:#0284c7,color:#0c4a6e;
classDef os fill:#f9fafb,stroke:#9ca3af,color:#374151,stroke-dasharray:3 3;
classDef proc fill:#f3f4f6,stroke:#6b7280,color:#111827;

class U,API,CLI entry
class LDS,CORE,DMN daemon
class COL,ANA,RESP,BASE,ML,LOG,ALR layer
class SQL db
class SYSMD,JRN,NETM,CRON os
```

---

### Architecture Summary

| Component | Role |
|------------|------|
| **Collection Layer** | Sequential collectors (system, process, network, filesystem, kernel) feed telemetry into the analysis stack. |
| **Analysis Layer** | Pure-Rust heuristic, signature, and ML-based anomaly detection engines operate on immutable telemetry batches. |
| **Response Layer** | Applies deterministic policy rules (alert, isolate, block) with cooldown and audit guarantees. |
| **Baseline Manager** | Handles baseline comparison and update cycles; persists all states in **SQLite** under `/var/lib/hardn/legion/legion.db`. |
| **SQLite Baseline DB** | The heuristics backbone — stores normalized telemetry, learned baselines, historical risk scores, and ML training data. |
| **Machine Learning Engine** | Uses SQLite data to train, cluster, and evaluate anomaly patterns in real-time. |
| **Logging & Alerts** | Unified journal logging and structured alert output via `systemd-journal`. |
| **Integration Services** | systemd, journald, cron, and NetworkManager used for lifecycle, logging, and telemetry scheduling. |

---